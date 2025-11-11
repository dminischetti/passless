<?php

declare(strict_types=1);

namespace Passless\Security;

use DateInterval;
use DateTimeImmutable;
use Passless\DB\Connector;
use Passless\Support\Log;
use Throwable;

final class GeoIpService
{
    public static function lookup(string $ip): ?array
    {
        if (!self::enabled() || !filter_var($ip, FILTER_VALIDATE_IP)) {
            return null;
        }

        try {
            $pdo = Connector::connection();
            $now = new DateTimeImmutable('now');
            $threshold = $now->sub(new DateInterval('P7D'));
            // CACHE: prefer cached results younger than seven days to avoid
            // hammering third-party APIs and to keep GeoIP lookups deterministic
            // for rate-limit calculations and alerting.
            $select = $pdo->prepare('SELECT country, raw_response, looked_up_at FROM geo_cache WHERE ip = :ip');
            $select->execute([':ip' => $ip]);
            $cached = $select->fetch();
            if ($cached && new DateTimeImmutable((string) $cached['looked_up_at']) > $threshold) {
                return [
                    'country' => $cached['country'] ?? null,
                    'raw' => json_decode((string) $cached['raw_response'], true) ?: null,
                ];
            }
        } catch (Throwable $exception) {
            Log::warning('Geo cache lookup failed', ['error' => $exception->getMessage()]);
        }

        $response = self::fetchRemote($ip);
        if ($response === null) {
            return null;
        }

        $country = $response['country'] ?? null;

        try {
            $pdo = Connector::connection();
            // CACHE: replace keeps the cache idempotent so repeated lookups do not
            // accumulate rows. Raw JSON is stored for post-incident analysis.
            $statement = $pdo->prepare(
                'REPLACE INTO geo_cache (ip, country, raw_response, looked_up_at) VALUES (:ip, :country, :raw_response, :looked_up_at)'
            );
            $statement->execute([
                ':ip' => $ip,
                ':country' => $country,
                ':raw_response' => json_encode($response, JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE),
                ':looked_up_at' => (new DateTimeImmutable('now'))->format('Y-m-d H:i:s'),
            ]);
        } catch (Throwable $exception) {
            Log::warning('Geo cache update failed', ['error' => $exception->getMessage()]);
        }

        return [
            'country' => $country,
            'raw' => $response,
        ];
    }

    private static function enabled(): bool
    {
        return passless_bool_env('GEOIP_ENABLED', false);
    }

    private static function fetchRemote(string $ip): ?array
    {
        $endpoint = str_replace('{IP}', rawurlencode($ip), (string) passless_env('GEOIP_ENDPOINT', 'https://ipapi.co/{IP}/json/'));
        $context = stream_context_create([
            'http' => [
                'timeout' => 3,
                'ignore_errors' => true,
            ],
        ]);

        try {
            $body = file_get_contents($endpoint, false, $context);
            if ($body === false) {
                return null;
            }
            $decoded = json_decode($body, true);
            if (!is_array($decoded)) {
                return null;
            }
            return $decoded;
        } catch (Throwable $exception) {
            Log::warning('Geo lookup failed', ['error' => $exception->getMessage()]);
            return null;
        }
    }
}
