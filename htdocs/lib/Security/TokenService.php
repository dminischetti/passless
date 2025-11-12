<?php

declare(strict_types=1);

namespace Passless\Security;

use DateInterval;
use DateTimeImmutable;
use Exception;
use Passless\DB\Connector;
use Passless\Support\AuditLogger;
use Passless\Support\Log;
use Passless\Support\SecurityEventLogger;
use PDO;

final class TokenService
{
    public static function createForUser(int $userId, string $email, string $ipAddress, string $userAgent): MagicLink
    {
        $selector = bin2hex(random_bytes(10));
        $token = self::encode(random_bytes(32));
        $hash = password_hash($token, PASSWORD_DEFAULT);
        $fingerprintHash = password_hash(self::fingerprintMaterial($ipAddress, $userAgent), PASSWORD_DEFAULT);

        $ttl = (int) \passless_env('MAGIC_LINK_TTL', '900');
        $expires = (new DateTimeImmutable('now'))->add(new DateInterval('PT' . max(60, $ttl) . 'S'));

        $pdo = Connector::connection();
        $statement = $pdo->prepare(
            'INSERT INTO login_tokens (selector, user_id, token_hash, fingerprint_hash, expires_at, ip_address, user_agent)
             VALUES (:selector, :user_id, :token_hash, :fingerprint_hash, :expires_at, :ip_address, :user_agent)'
        );
        $statement->execute([
            ':selector' => $selector,
            ':user_id' => $userId,
            ':token_hash' => $hash,
            ':fingerprint_hash' => $fingerprintHash,
            ':expires_at' => $expires->format('Y-m-d H:i:s'),
            ':ip_address' => $ipAddress,
            ':user_agent' => mb_substr($userAgent, 0, 255),
        ]);

        $magicUrl = self::buildLink($selector, $token);

        AuditLogger::record('magic_link.created', [
            'selector' => $selector,
            'user_id' => $userId,
            'ip' => $ipAddress,
        ]);

        return new MagicLink($email, $magicUrl, $expires);
    }

    public static function verify(string $selector, string $token, string $ipAddress, string $userAgent): TokenVerificationResult
    {
        $pdo = Connector::connection();
        $pdo->beginTransaction();

        try {
            $driver = strtolower((string) $pdo->getAttribute(PDO::ATTR_DRIVER_NAME));
            // SECURITY: read the token row inside the transaction. When MySQL is in use we
            // request a row-level lock (FOR UPDATE) so two concurrent verifications cannot
            // both succeed. SQLite is single-writer, so the transaction alone is sufficient.
            $query = 'SELECT lt.id, lt.user_id, lt.token_hash, lt.fingerprint_hash, lt.expires_at, lt.consumed_at, lt.user_agent, lt.ip_address, u.locked_until'
                . ' FROM login_tokens lt INNER JOIN users u ON u.id = lt.user_id WHERE selector = :selector';
            if ($driver === 'mysql') {
                $query .= ' FOR UPDATE';
            }

            $statement = $pdo->prepare($query);
            $statement->execute([':selector' => $selector]);
            $record = $statement->fetch(PDO::FETCH_ASSOC);

            if (!$record) {
                usleep(random_int(400000, 800000));
                $pdo->commit();
                SecurityEventLogger::record('token.missing', ['selector' => $selector, 'ip' => $ipAddress]);
                AuditLogger::record('magic_link.verify_missing', ['selector' => $selector, 'ip' => $ipAddress]);
                return new TokenVerificationResult(TokenVerificationResult::STATUS_INVALID);
            }

            $userId = (int) $record['user_id'];
            $lockedUntil = $record['locked_until'] ? new DateTimeImmutable($record['locked_until']) : null;
            if ($lockedUntil && $lockedUntil > new DateTimeImmutable('now')) {
                usleep(random_int(400000, 800000));
                $pdo->commit();
                SecurityEventLogger::record('account.locked_attempt', ['selector' => $selector, 'user_id' => $userId, 'ip' => $ipAddress]);
                AuditLogger::record('magic_link.verify_locked', ['selector' => $selector, 'user_id' => $userId]);
                return new TokenVerificationResult(TokenVerificationResult::STATUS_LOCKED, $userId, ['locked_until' => $lockedUntil->format(DATE_ATOM)]);
            }

            if ($record['consumed_at'] !== null) {
                usleep(random_int(400000, 800000));
                $pdo->commit();
                SecurityEventLogger::record('token.reuse_attempt', ['selector' => $selector, 'user_id' => $userId, 'ip' => $ipAddress]);
                AuditLogger::record('magic_link.verify_consumed', ['selector' => $selector, 'user_id' => $userId]);
                return new TokenVerificationResult(TokenVerificationResult::STATUS_CONSUMED, $userId);
            }

            if (new DateTimeImmutable($record['expires_at']) < new DateTimeImmutable('now')) {
                usleep(random_int(400000, 800000));
                $pdo->commit();
                SecurityEventLogger::record('token.expired_attempt', ['selector' => $selector, 'user_id' => $userId, 'ip' => $ipAddress]);
                AuditLogger::record('magic_link.verify_expired', ['selector' => $selector, 'user_id' => $userId]);
                return new TokenVerificationResult(TokenVerificationResult::STATUS_EXPIRED, $userId);
            }

            if (!password_verify($token, $record['token_hash'])) {
                usleep(random_int(400000, 800000));
                $pdo->commit();
                SecurityEventLogger::record('token.invalid_secret', ['selector' => $selector, 'user_id' => $userId, 'ip' => $ipAddress]);
                AuditLogger::record('magic_link.verify_invalid', ['selector' => $selector, 'user_id' => $userId]);
                return new TokenVerificationResult(TokenVerificationResult::STATUS_INVALID, $userId);
            }

            $fingerprintValid = password_verify(
                self::fingerprintMaterial($ipAddress, $userAgent),
                (string) $record['fingerprint_hash']
            );
            if (!$fingerprintValid) {
                usleep(random_int(400000, 800000));
                $pdo->commit();
                SecurityEventLogger::record('token.fingerprint_mismatch', [
                    'selector' => $selector,
                    'user_id' => $userId,
                    'expected_ip' => $record['ip_address'],
                    'attempt_ip' => $ipAddress,
                    'expected_agent' => $record['user_agent'],
                    'attempt_agent' => mb_substr($userAgent, 0, 255),
                ]);
                AuditLogger::record('magic_link.verify_fingerprint_mismatch', ['selector' => $selector, 'user_id' => $userId]);
                return new TokenVerificationResult(TokenVerificationResult::STATUS_FINGERPRINT_MISMATCH, $userId);
            }

            $update = $pdo->prepare('UPDATE login_tokens SET consumed_at = :consumed_at, consumed_ip = :ip, consumed_user_agent = :agent WHERE id = :id AND consumed_at IS NULL');
            $update->execute([
                ':consumed_at' => (new DateTimeImmutable('now'))->format('Y-m-d H:i:s'),
                ':ip' => $ipAddress,
                ':agent' => mb_substr($userAgent, 0, 255),
                ':id' => $record['id'],
            ]);

            Log::info('Magic link consumed', [
                'selector' => $selector,
                'user_id' => $userId,
                'ip' => $ipAddress,
            ]);
            AuditLogger::record('magic_link.verified', ['selector' => $selector, 'user_id' => $userId, 'ip' => $ipAddress]);

            $pdo->commit();

            return new TokenVerificationResult(TokenVerificationResult::STATUS_SUCCESS, $userId);
        } catch (Exception $exception) {
            $pdo->rollBack();
            Log::error('Token verification failed', ['error' => $exception->getMessage()]);
            return new TokenVerificationResult(TokenVerificationResult::STATUS_INVALID);
        }
    }

    private static function encode(string $bytes): string
    {
        return rtrim(strtr(base64_encode($bytes), '+/', '-_'), '=');
    }

    private static function buildLink(string $selector, string $token): string
    {
        return \passless_url('auth/verify.php?selector=' . rawurlencode($selector) . '&token=' . rawurlencode($token));
    }

    private static function fingerprintMaterial(string $ip, string $userAgent): string
    {
        $agent = $userAgent !== '' ? mb_strtolower($userAgent) : 'unknown-agent';
        $ipNormalized = $ip !== '' ? $ip : 'unknown-ip';
        return hash('sha256', $ipNormalized . '|' . $agent);
    }
}
