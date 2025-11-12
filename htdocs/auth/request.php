<?php

declare(strict_types=1);

require __DIR__ . '/../lib/bootstrap.php';

use Passless\DB\Connector;
use Passless\Mail\Mailer;
use Passless\Security\Captcha;
use Passless\Security\Csrf;
use Passless\Security\RateLimiter;
use Passless\Security\SessionAuth;
use Passless\Security\TokenService;
use Passless\Support\AuditLogger;
use Passless\Support\Exception\MailTransportException;
use Passless\Support\Log;
use Passless\Support\SecurityEventLogger;

$session = SessionAuth::instance();

if (($_SERVER['REQUEST_METHOD'] ?? 'GET') !== 'POST') {
    http_response_code(405);
    exit('Method Not Allowed');
}

if (!Csrf::validate($_POST['csrf_token'] ?? null)) {
    usleep(random_int(50000, 150000));
    $session->flash('error', 'Invalid session, please try again.');
    passless_redirect();
}

$email = strtolower(trim((string) ($_POST['email'] ?? '')));
if (!filter_var($email, FILTER_VALIDATE_EMAIL)) {
    usleep(random_int(50000, 150000));
    $session->flash('error', 'Please provide a valid email address.');
    passless_redirect();
}

$scope = 'request:' . hash('sha256', $email);
if (Captcha::isRequired($scope)) {
    $validCaptcha = Captcha::validate($scope, $_POST['captcha_answer'] ?? null, $_POST['captcha_token'] ?? null);
    if (!$validCaptcha) {
        usleep(random_int(50000, 150000));
        SecurityEventLogger::record('captcha.failed', ['email' => $email, 'ip' => $_SERVER['REMOTE_ADDR'] ?? 'unknown']);
        $session->flash('error', 'Please complete the verification challenge.');
        passless_redirect();
    }
}

$ip = $_SERVER['REMOTE_ADDR'] ?? 'unknown';
$decay = (int) passless_env('RATE_LIMIT_DECAY', '900');
$emailLimit = (int) passless_env('RATE_LIMIT_EMAIL', '5');
$ipLimit = (int) passless_env('RATE_LIMIT_IP', '10');
$comboLimit = (int) passless_env('RATE_LIMIT_EMAIL_IP', '6');

$emailLimiter = RateLimiter::hit('email', hash('sha256', $email), $emailLimit, $decay);
$ipLimiter = RateLimiter::hit('ip', $ip, $ipLimit, $decay);
$comboLimiter = RateLimiter::hit('email_ip', hash('sha256', $email . '|' . $ip), $comboLimit, $decay);

$captchaThreshold = (int) passless_env('CAPTCHA_THRESHOLD_EMAIL', '3');
if ($emailLimiter->count() >= $captchaThreshold || $comboLimiter->count() >= $captchaThreshold) {
    Captcha::requireChallenge($scope);
    $_SESSION['active_captcha_scope'] = $scope;
}

if ($emailLimiter->limited() || $ipLimiter->limited() || $comboLimiter->limited()) {
    $retry = max(
        $emailLimiter->retryAfter()->getTimestamp(),
        $ipLimiter->retryAfter()->getTimestamp(),
        $comboLimiter->retryAfter()->getTimestamp()
    );
    $retryAfter = gmdate('H:i:s \U\T\C', $retry);
    $_SESSION['resend_available_at'] = $retry;
    SecurityEventLogger::record('rate_limit.hit', [
        'email' => $email,
        'ip' => $ip,
        'retry_at' => $retryAfter,
    ]);
    $session->flash('error', 'Too many requests. Try again at ' . $retryAfter . '.');
    passless_redirect();
}

try {
    $pdo = Connector::connection();
    $pdo->beginTransaction();

    $select = $pdo->prepare('SELECT id, email, locked_until FROM users WHERE email = :email FOR UPDATE');
    $select->execute([':email' => $email]);
    $user = $select->fetch();

    if (!$user) {
        $insert = $pdo->prepare('INSERT INTO users (email, created_at) VALUES (:email, :created_at)');
        $now = (new \DateTimeImmutable('now'))->format('Y-m-d H:i:s');
        $insert->execute([
            ':email' => $email,
            ':created_at' => $now,
        ]);
        $userId = (int) $pdo->lastInsertId();
        $lockedUntil = null;
    } else {
        $userId = (int) $user['id'];
        $lockedUntil = $user['locked_until'] ? new \DateTimeImmutable((string) $user['locked_until']) : null;
    }

    if ($lockedUntil && $lockedUntil > new \DateTimeImmutable('now')) {
        $pdo->commit();
        SecurityEventLogger::record('account.locked_request', ['email' => $email, 'ip' => $ip]);
        $session->flash('error', 'We cannot send a link right now. Please contact support.');
        passless_redirect();
    }

    $pdo->commit();
} catch (\Throwable $exception) {
    if (isset($pdo) && $pdo->inTransaction()) {
        $pdo->rollBack();
    }
    Log::error('Failed to prepare magic link', ['error' => $exception->getMessage()]);
    $session->flash('error', 'Something went wrong. Please try again later.');
    passless_redirect();
}

$magicLink = TokenService::createForUser($userId, $email, $ip, $_SERVER['HTTP_USER_AGENT'] ?? '');

try {
    Mailer::sendMagicLink($email, $magicLink->url(), $magicLink->expiresAt());
} catch (MailTransportException $exception) {
    usleep(random_int(50000, 150000));
    SecurityEventLogger::record('mail.delivery_failed', [
        'email' => $email,
        'ip' => $ip,
        'error' => $exception->getMessage(),
    ]);
    Log::error('Magic link delivery failed', ['email' => $email, 'error' => $exception->getMessage()]);
    $session->flash('error', 'We could not send the magic link right now. Please try again later.');
    passless_redirect();
}
AuditLogger::record('magic_link.dispatched', ['user_id' => $userId, 'email' => $email, 'ip' => $ip]);
Log::info('Magic link generated', ['user' => $email, 'ip' => $ip]);

unset($_SESSION['active_captcha_scope']);

if (passless_env('APP_ENV', 'production') === 'development') {
    $_SESSION['last_magic_link'] = [
        'email' => $email,
        'url' => $magicLink->url(),
    ];
}

$retryWindow = max(
    $emailLimiter->retryAfter()->getTimestamp(),
    $ipLimiter->retryAfter()->getTimestamp(),
    $comboLimiter->retryAfter()->getTimestamp()
);
$_SESSION['resend_available_at'] = $retryWindow;

$session->flash('success', 'Magic link sent. Please check your inbox.');
passless_redirect();
