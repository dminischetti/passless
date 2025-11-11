<?php

declare(strict_types=1);

namespace Passless\DB;

use PDO;
use PDOException;
use Passless\Support\Exception\DatabaseException;
use Passless\Support\Log;

final class Connector
{
    private static ?PDO $pdo = null;

    public static function connection(): PDO
    {
        if (self::$pdo instanceof PDO) {
            return self::$pdo;
        }

        $driver = strtolower((string) \passless_env('DB_DRIVER', 'mysql'));

        if ($driver === 'sqlite') {
            $dsn = \passless_env('DB_DSN', 'sqlite::memory:');
            $username = null;
            $password = null;
        } else {
            $dsn = sprintf(
                'mysql:host=%s;port=%s;dbname=%s;charset=utf8mb4',
                \passless_env('DB_HOST', 'localhost'),
                \passless_env('DB_PORT', '3306'),
                \passless_env('DB_NAME', 'passless')
            );
            $username = (string) \passless_env('DB_USER', 'root');
            $password = (string) \passless_env('DB_PASS', '');
        }

        $options = [
            PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION,
            PDO::ATTR_DEFAULT_FETCH_MODE => PDO::FETCH_ASSOC,
            PDO::ATTR_EMULATE_PREPARES => false,
        ];

        try {
            self::$pdo = new PDO($dsn, $username, $password, $options);
        } catch (PDOException $exception) {
            Log::error('Database connection failed', ['error' => $exception->getMessage()]);
            throw new DatabaseException('Unable to connect to the database', 0, $exception);
        }

        return self::$pdo;
    }

    public static function setConnection(PDO $pdo): void
    {
        self::$pdo = $pdo;
    }
}
