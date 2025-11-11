<?php

declare(strict_types=1);

namespace Passless\Support;

use DateTimeImmutable;
use Passless\DB\Connector;
use Throwable;

final class SecurityEventLogger
{
    public static function record(string $type, array $context = []): void
    {
        try {
            $payload = json_encode($context, JSON_THROW_ON_ERROR | JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE);
        } catch (Throwable) {
            $payload = json_encode(['fallback' => true, 'context' => $context], JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE);
        }

        $pdo = Connector::connection();
        $statement = $pdo->prepare('INSERT INTO security_events (event_type, context, created_at) VALUES (:type, :context, :created_at)');
        $statement->execute([
            ':type' => $type,
            ':context' => $payload,
            ':created_at' => (new DateTimeImmutable('now'))->format('Y-m-d H:i:s'),
        ]);
    }
}
