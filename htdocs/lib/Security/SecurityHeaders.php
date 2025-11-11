<?php

declare(strict_types=1);

namespace Passless\Security;

final class SecurityHeaders
{
    public static function apply(): void
    {
        header("Content-Security-Policy: default-src 'self'; style-src 'self'; img-src 'self' data:; form-action 'self'; frame-ancestors 'none'");
        header('X-Frame-Options: DENY');
        header('Referrer-Policy: same-origin');
        header('X-Content-Type-Options: nosniff');
        header('X-Permitted-Cross-Domain-Policies: none');
        header('Cross-Origin-Resource-Policy: same-origin');
    }
}
