<?php

declare(strict_types=1);

require __DIR__ . '/../../lib/autoload.php';

if (!function_exists('passless_env')) {
    function passless_env(string $key, ?string $default = null): ?string
    {
        return $default;
    }
}

if (!function_exists('passless_bool_env')) {
    function passless_bool_env(string $key, bool $default = false): bool
    {
        return $default;
    }
}

if (!function_exists('passless_root')) {
    function passless_root(): string
    {
        return dirname(__DIR__, 2);
    }
}
