<?php

declare(strict_types=1);

use Passless\DB\Connector;
use Passless\Security\TokenService;
use Passless\Security\TokenVerificationResult;

register_test('TokenService verifies and consumes magic link', function (): void {
    passless_test_reset();

    $pdo = Connector::connection();
    $pdo->prepare('INSERT INTO users (email, created_at) VALUES (:email, :created_at)')->execute([
        ':email' => 'flow@example.com',
        ':created_at' => (new DateTimeImmutable('now'))->format('Y-m-d H:i:s'),
    ]);

    $userId = (int) $pdo->lastInsertId();

    $magicLink = TokenService::createForUser($userId, 'flow@example.com', '127.0.0.1', 'PasslessTest/1.0');
    $query = parse_url($magicLink->url(), PHP_URL_QUERY);
    parse_str((string) $query, $params);
    $selector = (string) ($params['selector'] ?? '');
    $token = (string) ($params['token'] ?? '');

    $result = TokenService::verify($selector, $token, '127.0.0.1', 'PasslessTest/1.0');
    assertTrue($result->isSuccess(), 'Magic link should verify successfully.');
    assertEquals(TokenVerificationResult::STATUS_SUCCESS, $result->status(), 'Status should be success.');

    $statement = $pdo->prepare('SELECT consumed_at FROM login_tokens WHERE selector = :selector');
    $statement->execute([':selector' => $selector]);
    $row = $statement->fetch();
    assertTrue(!empty($row['consumed_at']), 'Token should be marked as consumed.');
});

register_test('TokenService rejects fingerprint mismatches', function (): void {
    passless_test_reset();

    $pdo = Connector::connection();
    $pdo->prepare('INSERT INTO users (email, created_at) VALUES (:email, :created_at)')->execute([
        ':email' => 'mismatch@example.com',
        ':created_at' => (new DateTimeImmutable('now'))->format('Y-m-d H:i:s'),
    ]);

    $userId = (int) $pdo->lastInsertId();

    $magicLink = TokenService::createForUser($userId, 'mismatch@example.com', '127.0.0.1', 'PasslessTest/1.0');
    $query = parse_url($magicLink->url(), PHP_URL_QUERY);
    parse_str((string) $query, $params);
    $selector = (string) ($params['selector'] ?? '');
    $token = (string) ($params['token'] ?? '');

    $result = TokenService::verify($selector, $token, '203.0.113.1', 'DifferentAgent/2.0');
    assertEquals(TokenVerificationResult::STATUS_FINGERPRINT_MISMATCH, $result->status(), 'Fingerprint mismatch expected.');
});
