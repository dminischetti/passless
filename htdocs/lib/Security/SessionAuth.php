<?php

declare(strict_types=1);

namespace Passless\Security;

use DateTimeImmutable;
use Passless\DB\Connector;
use PDO;

final class SessionAuth
{
    private static ?self $instance = null;
    private static ?DatabaseSessionHandler $handler = null;

    public static function boot(DatabaseSessionHandler $handler): void
    {
        self::$handler = $handler;
    }

    public static function instance(): self
    {
        if (self::$instance instanceof self) {
            return self::$instance;
        }

        self::$instance = new self();
        return self::$instance;
    }

    public function currentUser(): ?array
    {
        return $_SESSION['user'] ?? null;
    }

    public function issuedAt(): DateTimeImmutable
    {
        $issued = $_SESSION['user']['issued_at'] ?? null;
        if ($issued === null) {
            return new DateTimeImmutable('now');
        }

        return new DateTimeImmutable($issued);
    }

    public function activeSessions(): array
    {
        $user = $this->currentUser();
        if ($user === null) {
            return [];
        }

        $pdo = Connector::connection();
        $statement = $pdo->prepare(
            'SELECT id, ip_address, user_agent, created_at, updated_at, expires_at, absolute_expires_at'
            . ' FROM sessions WHERE user_id = :user_id AND revoked_at IS NULL ORDER BY updated_at DESC'
        );
        $statement->execute([':user_id' => $user['id']]);

        $sessions = $statement->fetchAll(PDO::FETCH_ASSOC);

        return $sessions ?: [];
    }

    public function logIn(int $userId, string $email): void
    {
        $previous = session_id();
        session_regenerate_id(true);
        if (self::$handler) {
            self::$handler->revoke($previous);
        }

        $issuedAt = new DateTimeImmutable('now');
        $_SESSION['user'] = [
            'id' => $userId,
            'email' => $email,
            'is_admin' => $this->isAdminEmail($email),
            'issued_at' => $issuedAt->format(DATE_ATOM),
        ];
        Csrf::rotate();
    }

    public function logOut(): void
    {
        $previous = session_id();
        if (self::$handler) {
            self::$handler->revoke($previous);
        }

        $_SESSION = [];
        session_regenerate_id(true);
        Csrf::rotate();
    }

    public function revokeSession(string $sessionId): bool
    {
        $user = $this->currentUser();
        if ($user === null) {
            return false;
        }

        $pdo = Connector::connection();
        $statement = $pdo->prepare(
            'UPDATE sessions SET revoked_at = :revoked_at WHERE id = :id AND user_id = :user_id AND revoked_at IS NULL'
        );
        $statement->execute([
            ':revoked_at' => (new DateTimeImmutable('now'))->format('Y-m-d H:i:s'),
            ':id' => $sessionId,
            ':user_id' => $user['id'],
        ]);

        $revoked = $statement->rowCount() > 0;

        if ($revoked && $sessionId === session_id()) {
            $this->logOut();
        }

        return $revoked;
    }

    public function flash(string $type, string $message): void
    {
        $_SESSION['flash'] = [
            'type' => $type,
            'message' => $message,
        ];
    }

    public function isAdmin(): bool
    {
        $user = $this->currentUser();
        return $user !== null && !empty($user['is_admin']);
    }

    private function isAdminEmail(string $email): bool
    {
        $admin = passless_env('ADMIN_EMAIL');
        if (!$admin) {
            return false;
        }

        return hash_equals(mb_strtolower($admin), mb_strtolower($email));
    }
}
