<?php

declare(strict_types=1);

require __DIR__ . '/../../htdocs/lib/autoload.php';

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

if (!function_exists('passless_project_root')) {
    function passless_project_root(): string
    {
        return dirname(__DIR__, 2);
    }
}

if (!function_exists('passless_base_path')) {
    function passless_base_path(): string
    {
        return '';
    }
}

if (!function_exists('passless_path')) {
    function passless_path(string $relative = ''): string
    {
        $relative = ltrim($relative, '/');
        return $relative === '' ? '/' : '/' . $relative;
    }
}

if (!function_exists('passless_url')) {
    function passless_url(string $relative = ''): string
    {
        $relative = ltrim($relative, '/');
        return $relative === '' ? '/' : '/' . $relative;
    }
}

if (!function_exists('passless_redirect')) {
    function passless_redirect(string $relative = ''): void
    {
        // noop for static analysis bootstrap
    }
}
