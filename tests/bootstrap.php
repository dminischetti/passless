<?php

declare(strict_types=1);

use Passless\DB\Connector;

$pdo = new PDO('sqlite::memory:');
$pdo->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
$pdo->setAttribute(PDO::ATTR_DEFAULT_FETCH_MODE, PDO::FETCH_ASSOC);

ini_set('error_log', sys_get_temp_dir() . '/passless-tests.log');

$schema = [
    'CREATE TABLE users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        email TEXT NOT NULL UNIQUE,
        created_at TEXT NOT NULL,
        locked_until TEXT NULL,
        last_sign_in_at TEXT NULL,
        last_known_ip TEXT NULL,
        last_known_country TEXT NULL
    )',
    'CREATE TABLE login_tokens (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER NOT NULL,
        selector TEXT NOT NULL UNIQUE,
        token_hash TEXT NOT NULL,
        fingerprint_hash TEXT NOT NULL,
        expires_at TEXT NOT NULL,
        consumed_at TEXT NULL,
        consumed_ip TEXT NULL,
        consumed_user_agent TEXT NULL,
        ip_address TEXT NULL,
        user_agent TEXT NULL,
        created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE
    )',
    'CREATE TABLE sessions (
        id TEXT PRIMARY KEY,
        user_id INTEGER NULL,
        data BLOB NOT NULL,
        created_at TEXT NOT NULL,
        updated_at TEXT NOT NULL,
        expires_at TEXT NULL,
        absolute_expires_at TEXT NULL,
        ip_address TEXT NULL,
        user_agent TEXT NULL,
        revoked_at TEXT NULL
    )',
    'CREATE TABLE rate_limits (
        scope TEXT NOT NULL,
        identifier TEXT NOT NULL,
        count INTEGER NOT NULL,
        expires_at TEXT NOT NULL,
        last_seen TEXT NOT NULL,
        PRIMARY KEY(scope, identifier)
    )',
    'CREATE TABLE audit_logs (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        event TEXT NOT NULL,
        context TEXT NULL,
        created_at TEXT NOT NULL
    )',
    'CREATE TABLE security_events (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        event_type TEXT NOT NULL,
        context TEXT NULL,
        created_at TEXT NOT NULL
    )',
    'CREATE TABLE geo_cache (
        ip TEXT PRIMARY KEY,
        country TEXT NULL,
        raw_response TEXT NULL,
        looked_up_at TEXT NOT NULL
    )'
];

foreach ($schema as $sql) {
    $pdo->exec($sql);
}

$_ENV = array_merge($_ENV, [
    'APP_ENV' => 'testing',
    'APP_URL' => 'https://example.test',
    'MAGIC_LINK_TTL' => '900',
    'RATE_LIMIT_DECAY' => '60',
    'SESSION_COOKIE_SECURE' => '0',
    'SESSION_LIFETIME' => '600',
    'SESSION_ABSOLUTE_LIFETIME' => '3600',
]);

$_SERVER = array_merge($_SERVER, [
    'REMOTE_ADDR' => '127.0.0.1',
    'HTTP_USER_AGENT' => 'PHPUnit/Passless',
]);

$projectRoot = dirname(__DIR__);
$libPath = $projectRoot . '/htdocs/lib';

require $libPath . '/autoload.php';
require $libPath . '/Support/Log.php';
require $libPath . '/Support/AuditLogger.php';
require $libPath . '/Support/SecurityEventLogger.php';
require $libPath . '/DB/Connector.php';

Connector::setConnection($pdo);

require $libPath . '/bootstrap.php';
Connector::setConnection($pdo);

$GLOBALS['TESTS'] = [];

function register_test(string $name, callable $test): void {
    $GLOBALS['TESTS'][] = [$name, $test];
}

function assertTrue(bool $condition, string $message = ''): void {
    if (!$condition) {
        throw new RuntimeException($message !== '' ? $message : 'Failed asserting that condition is true.');
    }
}

function assertEquals(mixed $expected, mixed $actual, string $message = ''): void {
    if ($expected != $actual) {
        $default = sprintf('Failed asserting that %s matches expected %s.', var_export($actual, true), var_export($expected, true));
        throw new RuntimeException($message !== '' ? $message : $default);
    }
}

function passless_test_reset(): void {
    $pdo = Connector::connection();
    foreach (['login_tokens', 'sessions', 'rate_limits', 'audit_logs', 'security_events', 'geo_cache', 'users'] as $table) {
        $pdo->exec('DELETE FROM ' . $table);
    }
}
