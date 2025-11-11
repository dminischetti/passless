<?php

declare(strict_types=1);

namespace Passless\Security;

use DateTimeImmutable;

final class RateLimitResult
{
    public function __construct(
        private readonly bool $limited,
        private readonly int $count,
        private readonly DateTimeImmutable $expiresAt
    ) {
    }

    public function limited(): bool
    {
        return $this->limited;
    }

    public function count(): int
    {
        return $this->count;
    }

    public function retryAfter(): DateTimeImmutable
    {
        return $this->expiresAt;
    }
}
