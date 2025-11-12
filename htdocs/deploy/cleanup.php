<?php

declare(strict_types=1);

require dirname(__DIR__) . '/lib/bootstrap.php';

use Passless\DB\Connector;
use Passless\Support\Log;

$now = new DateTimeImmutable('now');
$pdo = Connector::connection();
$geoThreshold = $now->sub(new DateInterval('P30D'));

$results = [
    'login_tokens' => $pdo->prepare('DELETE FROM login_tokens WHERE (expires_at < :now) OR consumed_at IS NOT NULL'),
    'sessions' => $pdo->prepare('DELETE FROM sessions WHERE (expires_at IS NOT NULL AND expires_at < :now) OR (absolute_expires_at IS NOT NULL AND absolute_expires_at < :now) OR revoked_at IS NOT NULL'),
    'rate_limits' => $pdo->prepare('DELETE FROM rate_limits WHERE expires_at < :now'),
    'geo_cache' => $pdo->prepare('DELETE FROM geo_cache WHERE looked_up_at < :geo_threshold'),
];

$total = 0;

foreach ($results as $table => $statement) {
    if ($table === 'geo_cache') {
        $params = [':geo_threshold' => $geoThreshold->format('Y-m-d H:i:s')];
    } else {
        $params = [':now' => $now->format('Y-m-d H:i:s')];
    }

    $statement->execute($params);
    $count = $statement->rowCount();
    $total += $count;
    echo sprintf("Purged %d rows from %s\n", $count, $table);
}

Log::info('Cleanup job completed', ['total_deleted' => $total]);

echo sprintf("Cleanup complete at %s.\n", $now->format(DATE_ATOM));
