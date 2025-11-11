<?php

declare(strict_types=1);

namespace Passless\Security;

use DateInterval;
use DateTimeImmutable;
use Passless\DB\Connector;
use PDO;
use SessionHandlerInterface;

final class DatabaseSessionHandler implements SessionHandlerInterface
{
    private int $lifetime;
    private ?int $absoluteLifetime;
    private int $refreshInterval;

    public function __construct(int $lifetime, ?int $absoluteLifetime = null, ?int $refreshInterval = null)
    {
        $this->lifetime = max(60, $lifetime);
        $this->absoluteLifetime = $absoluteLifetime;
        $this->refreshInterval = $refreshInterval ?? max(60, (int) floor($this->lifetime / 3));
    }

    public function open($savePath, $sessionName): bool
    {
        return true;
    }

    public function close(): bool
    {
        return true;
    }

    public function read($id): string
    {
        $pdo = Connector::connection();
        $statement = $pdo->prepare('SELECT data, expires_at, absolute_expires_at, revoked_at FROM sessions WHERE id = :id');
        $statement->execute([':id' => $id]);
        $session = $statement->fetch(PDO::FETCH_ASSOC);

        if (!$session) {
            return '';
        }

        $now = new DateTimeImmutable('now');
        if (
            ($session['expires_at'] !== null && new DateTimeImmutable($session['expires_at']) < $now) ||
            ($session['absolute_expires_at'] !== null && new DateTimeImmutable($session['absolute_expires_at']) < $now) ||
            $session['revoked_at'] !== null
        ) {
            $this->destroy($id);
            return '';
        }

        return (string) $session['data'];
    }

    public function write($id, $data): bool
    {
        $pdo = Connector::connection();
        $now = new DateTimeImmutable('now');

        // PERFORMANCE: Sliding expiration only updates when the configured refresh
        // interval has elapsed since the last write. This avoids hot-row contention
        // from updating expires_at on every request while still extending sessions
        // during active use. The trade-off is that a user might time out slightly
        // earlier if their final action lands just before the refresh window opens.
        $select = $pdo->prepare('SELECT expires_at, absolute_expires_at, updated_at FROM sessions WHERE id = :id');
        $select->execute([':id' => $id]);
        $existing = $select->fetch(PDO::FETCH_ASSOC) ?: null;

        $expiresAt = $now->add(new DateInterval('PT' . $this->lifetime . 'S'));
        if ($existing && $existing['expires_at']) {
            $lastUpdate = new DateTimeImmutable($existing['updated_at']);
            if ($lastUpdate->add(new DateInterval('PT' . $this->refreshInterval . 'S')) > $now) {
                $expiresAt = new DateTimeImmutable($existing['expires_at']);
            }
        }

        $absoluteExpiresAt = null;
        if ($this->absoluteLifetime !== null) {
            if ($existing && $existing['absolute_expires_at']) {
                $absoluteExpiresAt = new DateTimeImmutable($existing['absolute_expires_at']);
            } else {
                $absoluteExpiresAt = $now->add(new DateInterval('PT' . $this->absoluteLifetime . 'S'));
            }
        }

        $driver = strtolower((string) $pdo->getAttribute(PDO::ATTR_DRIVER_NAME));
        // SECURITY: the UPSERT keeps session data consistent and preserves the
        // original absolute expiration. We never extend the absolute lifetime
        // beyond the first creation, which lets operators enforce maximum session age.
        if ($driver === 'mysql') {
            $sql = 'INSERT INTO sessions (id, user_id, data, created_at, updated_at, expires_at, absolute_expires_at, ip_address, user_agent)
                VALUES (:id, :user_id, :data, :created_at, :updated_at, :expires_at, :absolute_expires_at, :ip_address, :user_agent)
                ON DUPLICATE KEY UPDATE
                    user_id = :user_id,
                    data = :data,
                    updated_at = :updated_at,
                    expires_at = :expires_at,
                    ip_address = :ip_address,
                    user_agent = :user_agent,
                    absolute_expires_at = IFNULL(absolute_expires_at, :absolute_expires_at)';
        } else {
            // SQLite mirrors the same guarantees using COALESCE so the
            // absolute expiry stays anchored to the first session creation.
            $sql = 'INSERT INTO sessions (id, user_id, data, created_at, updated_at, expires_at, absolute_expires_at, ip_address, user_agent)
                VALUES (:id, :user_id, :data, :created_at, :updated_at, :expires_at, :absolute_expires_at, :ip_address, :user_agent)
                ON CONFLICT(id) DO UPDATE SET
                    user_id = excluded.user_id,
                    data = excluded.data,
                    updated_at = excluded.updated_at,
                    expires_at = excluded.expires_at,
                    ip_address = excluded.ip_address,
                    user_agent = excluded.user_agent,
                    absolute_expires_at = COALESCE(sessions.absolute_expires_at, excluded.absolute_expires_at)';
        }

        $statement = $pdo->prepare($sql);

        $statement->bindValue(':id', $id);
        $userId = $_SESSION['user']['id'] ?? null;
        if ($userId === null) {
            $statement->bindValue(':user_id', null, PDO::PARAM_NULL);
        } else {
            $statement->bindValue(':user_id', (int) $userId, PDO::PARAM_INT);
        }

        $statement->bindValue(':data', $data, PDO::PARAM_LOB);
        $statement->bindValue(':created_at', $now->format('Y-m-d H:i:s'));
        $statement->bindValue(':updated_at', $now->format('Y-m-d H:i:s'));
        $statement->bindValue(':expires_at', $expiresAt->format('Y-m-d H:i:s'));
        if ($absoluteExpiresAt instanceof DateTimeImmutable) {
            $statement->bindValue(':absolute_expires_at', $absoluteExpiresAt->format('Y-m-d H:i:s'));
        } else {
            $statement->bindValue(':absolute_expires_at', null, PDO::PARAM_NULL);
        }
        $statement->bindValue(':ip_address', $_SERVER['REMOTE_ADDR'] ?? 'unknown');
        $statement->bindValue(':user_agent', mb_substr($_SERVER['HTTP_USER_AGENT'] ?? 'cli', 0, 255));

        return $statement->execute();
    }

    public function destroy($id): bool
    {
        $pdo = Connector::connection();
        $statement = $pdo->prepare('UPDATE sessions SET revoked_at = :revoked_at WHERE id = :id');
        $statement->execute([
            ':revoked_at' => (new DateTimeImmutable('now'))->format('Y-m-d H:i:s'),
            ':id' => $id,
        ]);

        return true;
    }

    public function gc($max_lifetime): int|false
    {
        $pdo = Connector::connection();
        $statement = $pdo->prepare(
            'DELETE FROM sessions WHERE (expires_at IS NOT NULL AND expires_at < :now)
             OR (absolute_expires_at IS NOT NULL AND absolute_expires_at < :now)
             OR revoked_at IS NOT NULL'
        );
        $statement->execute([':now' => (new DateTimeImmutable('now'))->format('Y-m-d H:i:s')]);

        return $statement->rowCount();
    }

    public function revoke(string $id): void
    {
        $this->destroy($id);
    }
}
