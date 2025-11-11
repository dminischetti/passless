<?php

declare(strict_types=1);

namespace Passless\Security;

final class TokenVerificationResult
{
    public const STATUS_SUCCESS = 'success';
    public const STATUS_INVALID = 'invalid';
    public const STATUS_EXPIRED = 'expired';
    public const STATUS_CONSUMED = 'consumed';
    public const STATUS_FINGERPRINT_MISMATCH = 'fingerprint_mismatch';
    public const STATUS_LOCKED = 'locked';

    public function __construct(
        private readonly string $status,
        private readonly ?int $userId = null,
        private readonly ?array $details = null
    ) {
    }

    public function status(): string
    {
        return $this->status;
    }

    public function userId(): ?int
    {
        return $this->userId;
    }

    public function details(): ?array
    {
        return $this->details;
    }

    public function isSuccess(): bool
    {
        return $this->status === self::STATUS_SUCCESS && $this->userId !== null;
    }
}
