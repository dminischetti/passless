<?php
/**
 * Lightweight load-test harness for Passless security services.
 *
 * Usage: php tools/load_test.php
 *
 * Leverages the SQLite-backed test bootstrap to create magic links,
 * verify them, and exercise the rate limiter. Results are printed to
 * STDOUT for quick inclusion in documentation or regression tracking.
 */

declare(strict_types=1);

use Passless\DB\Connector;
use Passless\Security\RateLimiter;
use Passless\Security\TokenService;

require __DIR__ . '/../tests/bootstrap.php';

$pdo = Connector::connection();
$pdo->exec("DELETE FROM users");
$pdo->exec("INSERT INTO users (email, created_at) VALUES ('demo@passless.test', datetime('now'))");
$userId = (int) $pdo->lastInsertId();

// Keep iterations modest; verification jitter sleeps 400-800ms per token.
$iterations = 10;
$tokens = [];
$start = microtime(true);
for ($i = 0; $i < $iterations; $i++) {
    $magic = TokenService::createForUser($userId, 'demo@passless.test', '203.0.113.1', 'BenchBot/1.0');
    $tokens[] = $magic;
}
$creationDuration = microtime(true) - $start;

$start = microtime(true);
$success = 0;
foreach ($tokens as $magic) {
    $url = $magic->url();
    $parts = parse_url($url);
    $query = [];
    if (isset($parts['query'])) {
        parse_str($parts['query'], $query);
    }
    $selector = $query['selector'] ?? '';
    $token = $query['token'] ?? '';
    $result = TokenService::verify($selector, $token, '203.0.113.1', 'BenchBot/1.0');
    if ($result->isSuccess()) {
        $success++;
    }
}
$verificationDuration = microtime(true) - $start;

$start = microtime(true);
for ($i = 0; $i < $iterations; $i++) {
    RateLimiter::hit('bench_email', 'demo@passless.test', 1000, 60);
    RateLimiter::hit('bench_ip', '203.0.113.1', 1000, 60);
}
$rateDuration = microtime(true) - $start;

printf("Generated %d magic links in %.3f seconds (%.1f links/sec)\n", $iterations, $creationDuration, $iterations / max($creationDuration, 0.0001));
printf("Verified %d magic links in %.3f seconds (%.1f verifications/sec)\n", $success, $verificationDuration, $success / max($verificationDuration, 0.0001));
printf("Executed %d dual rate-limit hits in %.3f seconds (%.1f operations/sec)\n", $iterations, $rateDuration, ($iterations * 2) / max($rateDuration, 0.0001));
