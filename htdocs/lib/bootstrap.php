<?php

declare(strict_types=1);

use Passless\Security\Captcha;
use Passless\Security\Csrf;
use Passless\Security\DatabaseSessionHandler;
use Passless\Security\SecurityHeaders;
use Passless\Security\SessionAuth;

if (defined('PASSLESS_BOOTSTRAPPED')) {
    return;
}

define('PASSLESS_BOOTSTRAPPED', true);

require_once __DIR__ . '/autoload.php';
require_once __DIR__ . '/Support/Exception/PasslessException.php';
require_once __DIR__ . '/Support/Exception/DatabaseException.php';
require_once __DIR__ . '/Support/Exception/MailTransportException.php';
require_once __DIR__ . '/Support/Exception/SecurityException.php';
require_once __DIR__ . '/Support/Log.php';
require_once __DIR__ . '/Support/AuditLogger.php';
require_once __DIR__ . '/Support/SecurityEventLogger.php';
require_once __DIR__ . '/DB/Connector.php';
require_once __DIR__ . '/Security/SecurityHeaders.php';
require_once __DIR__ . '/Security/Csrf.php';
require_once __DIR__ . '/Security/RateLimiter.php';
require_once __DIR__ . '/Security/RateLimitResult.php';
require_once __DIR__ . '/Security/TokenService.php';
require_once __DIR__ . '/Security/TokenVerificationResult.php';
require_once __DIR__ . '/Security/MagicLink.php';
require_once __DIR__ . '/Security/DatabaseSessionHandler.php';
require_once __DIR__ . '/Security/SessionAuth.php';
require_once __DIR__ . '/Security/Captcha.php';
require_once __DIR__ . '/Security/GeoIpService.php';
require_once __DIR__ . '/Mail/Mailer.php';
require_once __DIR__ . '/Mail/Templates/MagicLinkTemplate.php';

if (!function_exists('passless_load_env')) {
    function passless_load_env(string $file): array
    {
        $values = [];

        if (is_readable($file)) {
            $lines = file($file, FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES);
            foreach ($lines as $line) {
                $line = trim($line);
                if ($line === '' || str_starts_with($line, '#')) {
                    continue;
                }
                if (!str_contains($line, '=')) {
                    continue;
                }
                [$key, $value] = array_map('trim', explode('=', $line, 2));
                $values[$key] = trim($value, "\"' ");
            }
        }

        foreach ($_ENV as $key => $value) {
            $values[$key] = $value;
        }

        foreach ($_SERVER as $key => $value) {
            if (is_string($value)) {
                $values[$key] = $value;
            }
        }

        return $values;
    }
}

if (!function_exists('passless_env')) {
    function passless_env(string $key, ?string $default = null): ?string
    {
        $value = $GLOBALS['PASSLESS_ENV'][$key] ?? null;
        if ($value === null) {
            $envValue = getenv($key);
            if ($envValue !== false) {
                $value = $envValue;
            }
        }

        return $value ?? $default;
    }
}

if (!function_exists('passless_bool_env')) {
    function passless_bool_env(string $key, bool $default = false): bool
    {
        $value = passless_env($key);
        if ($value === null) {
            return $default;
        }

        return in_array(strtolower($value), ['1', 'true', 'yes', 'on'], true);
    }
}

if (!function_exists('passless_root')) {
    function passless_root(): string
    {
        return $GLOBALS['PASSLESS_ROOT'] ?? getcwd();
    }
}

$root = dirname(__DIR__);
$GLOBALS['PASSLESS_ROOT'] = $root;
$GLOBALS['PASSLESS_ENV'] = passless_load_env($root . '/.env');

date_default_timezone_set(passless_env('APP_TIMEZONE', 'UTC'));

ini_set('session.use_strict_mode', '1');
ini_set('session.use_only_cookies', '1');
ini_set('session.cookie_httponly', '1');
ini_set('session.cookie_secure', passless_bool_env('SESSION_COOKIE_SECURE', true) ? '1' : '0');
ini_set('session.cookie_samesite', 'Lax');

SecurityHeaders::apply();

$cookieLifetime = (int) passless_env('SESSION_COOKIE_LIFETIME', '86400');
$cookieParams = [
    'lifetime' => $cookieLifetime,
    'path' => '/',
    'domain' => passless_env('SESSION_COOKIE_DOMAIN') ?: '',
    'secure' => passless_bool_env('SESSION_COOKIE_SECURE', true),
    'httponly' => true,
    'samesite' => 'Lax',
];

session_name(passless_env('SESSION_NAME', 'PASSLESSSESSID'));
session_set_cookie_params($cookieParams);

$handler = new DatabaseSessionHandler(
    (int) passless_env('SESSION_LIFETIME', '1800'),
    passless_env('SESSION_ABSOLUTE_LIFETIME') !== null ? (int) passless_env('SESSION_ABSOLUTE_LIFETIME') : null,
    passless_env('SESSION_REFRESH_INTERVAL') !== null ? (int) passless_env('SESSION_REFRESH_INTERVAL') : null
);

session_set_save_handler($handler, true);
session_start();

SessionAuth::boot($handler);
Csrf::token();

if (!isset($_SESSION['captcha_required'])) {
    $_SESSION['captcha_required'] = [];
}
if (!isset($_SESSION['captcha_answers'])) {
    $_SESSION['captcha_answers'] = [];
}
