<?php

declare(strict_types=1);

namespace Passless\Security;

use DateTimeImmutable;

final class MagicLink
{
    public function __construct(
        private readonly string $email,
        private readonly string $url,
        private readonly DateTimeImmutable $expiresAt
    ) {
    }

    public function email(): string
    {
        return $this->email;
    }

    public function url(): string
    {
        return $this->url;
    }

    public function expiresAt(): DateTimeImmutable
    {
        return $this->expiresAt;
    }
}
