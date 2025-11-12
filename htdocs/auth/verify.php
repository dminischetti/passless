<?php

declare(strict_types=1);

require __DIR__ . '/../lib/bootstrap.php';

use Passless\DB\Connector;
use Passless\Mail\Mailer;
use Passless\Security\GeoIpService;
use Passless\Security\RateLimiter;
use Passless\Security\SessionAuth;
use Passless\Security\TokenService;
use Passless\Security\TokenVerificationResult;
use Passless\Support\AuditLogger;
use Passless\Support\Log;
use Passless\Support\SecurityEventLogger;

$session = SessionAuth::instance();
$selector = trim((string) ($_GET['selector'] ?? ''));
$token = trim((string) ($_GET['token'] ?? ''));

if ($selector === '' || $token === '') {
    usleep(random_int(400000, 800000));
    $session->flash('error', 'The magic link is invalid or incomplete.');
    passless_redirect();
}

$ip = $_SERVER['REMOTE_ADDR'] ?? 'unknown';
$userAgent = $_SERVER['HTTP_USER_AGENT'] ?? '';
$verifyLimit = (int) passless_env('RATE_LIMIT_VERIFY', '10');
$decay = (int) passless_env('RATE_LIMIT_DECAY', '900');

$limiter = RateLimiter::hit('verify', hash('sha256', $ip . $selector), $verifyLimit, $decay);
if ($limiter->limited()) {
    $retry = gmdate('H:i:s \U\T\C', $limiter->retryAfter()->getTimestamp());
    SecurityEventLogger::record('verify.rate_limit', ['ip' => $ip, 'selector' => $selector, 'retry_at' => $retry]);
    $session->flash('error', 'Too many verification attempts. Try again at ' . $retry . '.');
    passless_redirect();
}

$result = TokenService::verify($selector, $token, $ip, $userAgent);

if ($result->isSuccess()) {
    $userId = $result->userId();
    try {
        $pdo = Connector::connection();
        $statement = $pdo->prepare('SELECT id, email, locked_until, last_known_ip, last_known_country FROM users WHERE id = :id');
        $statement->execute([':id' => $userId]);
        $user = $statement->fetch();
    } catch (\Throwable $exception) {
        Log::error('Failed to create session during verification', ['error' => $exception->getMessage()]);
        $session->flash('error', 'Unable to sign you in. Please request a new link.');
        passless_redirect();
    }

    if (!$user) {
        Log::warning('Verified token without matching user', ['user_id' => $userId]);
        $session->flash('error', 'Unable to sign you in. Please request a new link.');
        passless_redirect();
    }

    if ($user['locked_until']) {
        $lockedUntil = new \DateTimeImmutable((string) $user['locked_until']);
        if ($lockedUntil > new \DateTimeImmutable('now')) {
            $session->flash('error', 'This account is temporarily locked.');
            passless_redirect();
        }
    }

    $geo = GeoIpService::lookup($ip);
    $country = $geo['country'] ?? null;
    $previousIp = $user['last_known_ip'] ?? null;
    $previousCountry = $user['last_known_country'] ?? null;

    $update = $pdo->prepare('UPDATE users SET last_sign_in_at = :signed_at, last_known_ip = :ip, last_known_country = :country, locked_until = NULL WHERE id = :id');
    $update->execute([
        ':signed_at' => (new \DateTimeImmutable('now'))->format('Y-m-d H:i:s'),
        ':ip' => $ip,
        ':country' => $country,
        ':id' => $user['id'],
    ]);

    if (($previousCountry && $country && $previousCountry !== $country) || ($previousIp && $previousIp !== $ip)) {
        SecurityEventLogger::record('login.location_change', [
            'user_id' => $user['id'],
            'previous_country' => $previousCountry,
            'current_country' => $country,
            'previous_ip' => $previousIp,
            'current_ip' => $ip,
        ]);
        Mailer::sendSecurityAlert(
            (string) $user['email'],
            'New Passless sign-in location detected',
            sprintf('We noticed a sign-in from %s (%s). If this was not you, revoke sessions immediately.', $ip, $country ?: 'unknown location')
        );
    }

    $session->logIn((int) $user['id'], (string) $user['email']);
    unset($_SESSION['last_magic_link']);
    RateLimiter::clear('verify_fail_user', (string) $user['id']);
    RateLimiter::clear('verify_ip_fail', hash('sha256', $ip));
    Log::info('User signed in', ['user_id' => (int) $user['id'], 'ip' => $ip]);
    AuditLogger::record('session.created', ['user_id' => (int) $user['id'], 'ip' => $ip]);

    $session->flash('success', 'You are now signed in.');
    passless_redirect('app.php');
}

usleep(random_int(400000, 800000));
$details = $result->details() ?? [];
$userId = $result->userId();

if ($userId !== null) {
    $lockThreshold = (int) passless_env('ACCOUNT_LOCK_THRESHOLD', '5');
    $lockWindow = (int) passless_env('ACCOUNT_LOCK_WINDOW', '900');
    $lockDuration = (int) passless_env('ACCOUNT_LOCK_DURATION', '900');

    $failLimiter = RateLimiter::hit('verify_fail_user', (string) $userId, $lockThreshold, $lockWindow);
    if ($failLimiter->limited()) {
        $lockedUntil = (new \DateTimeImmutable('now'))->add(new \DateInterval('PT' . max(300, $lockDuration) . 'S'));
        $pdo = Connector::connection();
        $update = $pdo->prepare('UPDATE users SET locked_until = :locked_until WHERE id = :id');
        $update->execute([
            ':locked_until' => $lockedUntil->format('Y-m-d H:i:s'),
            ':id' => $userId,
        ]);
        SecurityEventLogger::record('account.locked', ['user_id' => $userId, 'until' => $lockedUntil->format(DATE_ATOM)]);
        AuditLogger::record('account.locked', ['user_id' => $userId, 'reason' => $result->status()]);

        $emailStmt = $pdo->prepare('SELECT email FROM users WHERE id = :id');
        $emailStmt->execute([':id' => $userId]);
        if ($emailRow = $emailStmt->fetch()) {
            Mailer::sendSecurityAlert(
                (string) $emailRow['email'],
                'Passless account locked',
                'We detected repeated invalid sign-in attempts and temporarily locked your account.'
            );
        }
    }

    RateLimiter::hit('verify_ip_fail', hash('sha256', $ip), $lockThreshold, $lockWindow);
}

switch ($result->status()) {
    case TokenVerificationResult::STATUS_LOCKED:
        $session->flash('error', 'This account is temporarily locked.');
        break;
    case TokenVerificationResult::STATUS_FINGERPRINT_MISMATCH:
        $session->flash('error', 'The magic link cannot be used from this device.');
        break;
    case TokenVerificationResult::STATUS_EXPIRED:
        $session->flash('error', 'The magic link has expired. Please request a new one.');
        break;
    case TokenVerificationResult::STATUS_CONSUMED:
        $session->flash('error', 'That magic link was already used.');
        break;
    default:
        $session->flash('error', 'The magic link has expired or was already used.');
        break;
}

passless_redirect();
