<?php

declare(strict_types=1);

use Passless\DB\Connector;
use Passless\Security\TokenService;
use Passless\Security\TokenVerificationResult;

register_test('TokenService verifies valid token', function (): void {
    passless_test_reset();
    $pdo = Connector::connection();
    $now = (new \DateTimeImmutable('now'))->format('Y-m-d H:i:s');
    $pdo->prepare('INSERT INTO users (email, created_at) VALUES (:email, :created_at)')->execute([
        ':email' => 'alice@example.com',
        ':created_at' => $now,
    ]);
    $userId = (int) $pdo->lastInsertId();

    $link = TokenService::createForUser($userId, 'alice@example.com', '203.0.113.1', 'TestBrowser/1.0');
    $parts = parse_url($link->url());
    parse_str($parts['query'] ?? '', $params);

    $result = TokenService::verify($params['selector'], $params['token'], '203.0.113.1', 'TestBrowser/1.0');
    assertTrue($result->isSuccess(), 'Expected verification to succeed.');
    assertEquals($userId, $result->userId(), 'Expected correct user id.');
});

register_test('TokenService rejects fingerprint mismatch', function (): void {
    passless_test_reset();
    $pdo = Connector::connection();
    $now = (new \DateTimeImmutable('now'))->format('Y-m-d H:i:s');
    $pdo->prepare('INSERT INTO users (email, created_at) VALUES (:email, :created_at)')->execute([
        ':email' => 'bob@example.com',
        ':created_at' => $now,
    ]);
    $userId = (int) $pdo->lastInsertId();

    $link = TokenService::createForUser($userId, 'bob@example.com', '198.51.100.2', 'Fingerprint/1.0');
    $parts = parse_url($link->url());
    parse_str($parts['query'] ?? '', $params);

    $result = TokenService::verify($params['selector'], $params['token'], '198.51.100.99', 'OtherAgent/2.0');
    assertEquals(TokenVerificationResult::STATUS_FINGERPRINT_MISMATCH, $result->status(), 'Expected fingerprint mismatch status.');
    assertTrue(!$result->isSuccess(), 'Fingerprint mismatch should not succeed.');
});

register_test('TokenService invalid token increments lockout counters', function (): void {
    passless_test_reset();
    $pdo = Connector::connection();
    $now = (new \DateTimeImmutable('now'))->format('Y-m-d H:i:s');
    $pdo->prepare('INSERT INTO users (email, created_at) VALUES (:email, :created_at)')->execute([
        ':email' => 'carol@example.com',
        ':created_at' => $now,
    ]);
    $userId = (int) $pdo->lastInsertId();

    $link = TokenService::createForUser($userId, 'carol@example.com', '192.0.2.10', 'Agent/1.0');
    $parts = parse_url($link->url());
    parse_str($parts['query'] ?? '', $params);

    $result = TokenService::verify($params['selector'], 'wrong-token', '192.0.2.10', 'Agent/1.0');
    assertEquals(TokenVerificationResult::STATUS_INVALID, $result->status());
});
