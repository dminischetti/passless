<?php

declare(strict_types=1);

namespace Passless\Security;

use DateInterval;
use DateTimeImmutable;
use Passless\DB\Connector;
use PDO;

final class RateLimiter
{
    public static function hit(string $scope, string $identifier, int $limit, int $decaySeconds): RateLimitResult
    {
        $pdo = Connector::connection();
        $now = new DateTimeImmutable('now');
        $expiresAt = $now->add(new DateInterval('PT' . max(1, $decaySeconds) . 'S'));
        $driver = strtolower((string) $pdo->getAttribute(PDO::ATTR_DRIVER_NAME));

        if ($driver === 'mysql') {
            // SECURITY: a single UPSERT keeps the counter accurate under concurrency.
            // The IF() expressions reset the window when expired while ensuring we
            // never drop increments. This mirrors the single atomic query pattern
            // discussed in the project docs and survives abrupt PHP shutdowns.
            $sql = 'INSERT INTO rate_limits (scope, identifier, count, expires_at, last_seen) VALUES (:scope, :identifier, 1, :expires_at, :now)
                ON DUPLICATE KEY UPDATE
                    count = IF(expires_at < :now, 1, count + 1),
                    expires_at = IF(expires_at < :now, :expires_at, expires_at),
                    last_seen = :now';
        } else {
            // SQLite mirrors the same behaviour using CASE expressions within ON CONFLICT.
            $sql = 'INSERT INTO rate_limits (scope, identifier, count, expires_at, last_seen) VALUES (:scope, :identifier, 1, :expires_at, :now)
                ON CONFLICT(scope, identifier) DO UPDATE SET
                    count = CASE WHEN expires_at < :now THEN 1 ELSE count + 1 END,
                    expires_at = CASE WHEN expires_at < :now THEN :expires_at ELSE expires_at END,
                    last_seen = :now';
        }

        $statement = $pdo->prepare($sql);
        $statement->execute([
            ':scope' => $scope,
            ':identifier' => $identifier,
            ':expires_at' => $expiresAt->format('Y-m-d H:i:s'),
            ':now' => $now->format('Y-m-d H:i:s'),
        ]);

        $select = $pdo->prepare('SELECT count, expires_at FROM rate_limits WHERE scope = :scope AND identifier = :identifier');
        $select->execute([
            ':scope' => $scope,
            ':identifier' => $identifier,
        ]);

        $record = $select->fetch(PDO::FETCH_ASSOC);
        if (!$record) {
            return new RateLimitResult(false, 0, $expiresAt);
        }

        $count = (int) $record['count'];
        $expiry = new DateTimeImmutable($record['expires_at']);
        $limited = $count > $limit;

        return new RateLimitResult($limited, $count, $expiry);
    }

    public static function clear(string $scope, string $identifier): void
    {
        $pdo = Connector::connection();
        $statement = $pdo->prepare('DELETE FROM rate_limits WHERE scope = :scope AND identifier = :identifier');
        $statement->execute([
            ':scope' => $scope,
            ':identifier' => $identifier,
        ]);
    }
}
