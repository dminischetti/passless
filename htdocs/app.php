<?php

declare(strict_types=1);

require __DIR__ . '/lib/bootstrap.php';

use Passless\DB\Connector;
use Passless\Security\Csrf;
use Passless\Security\SessionAuth;

$session = SessionAuth::instance();
$user = $session->currentUser();

if ($user === null) {
    header('Location: /');
    exit;
}

$csrfToken = Csrf::token();
$flash = $_SESSION['flash'] ?? null;
unset($_SESSION['flash']);
$activeSessions = $session->activeSessions();
$currentSessionId = session_id();

$pdo = Connector::connection();
$securityEventsStmt = $pdo->prepare('SELECT event_type, context, created_at FROM security_events ORDER BY created_at DESC LIMIT 50');
$securityEventsStmt->execute();
$rawSecurityEvents = $securityEventsStmt->fetchAll(PDO::FETCH_ASSOC) ?: [];

$auditStmt = $pdo->prepare('SELECT event, context, created_at FROM audit_logs ORDER BY created_at DESC LIMIT 50');
$auditStmt->execute();
$rawAuditLogs = $auditStmt->fetchAll(PDO::FETCH_ASSOC) ?: [];

function passless_decode_array(?string $context): array {
    if ($context === null || $context === '') {
        return [];
    }

    $decoded = json_decode($context, true);
    return is_array($decoded) ? $decoded : ['raw' => $context];
}

$securityEvents = array_values(array_filter(array_map(static function (array $event) use ($user) {
    $context = passless_decode_array($event['context'] ?? null);
    if (isset($context['user_id']) && $user && (int) $context['user_id'] !== (int) $user['id']) {
        return null;
    }

    return [
        'time' => $event['created_at'],
        'type' => $event['event_type'],
        'context' => $context,
    ];
}, $rawSecurityEvents)));

$auditLogs = array_values(array_filter(array_map(static function (array $log) use ($user) {
    $context = passless_decode_array($log['context'] ?? null);
    if (isset($context['user_id']) && $user && (int) $context['user_id'] !== (int) $user['id']) {
        return null;
    }

    return [
        'time' => $log['created_at'],
        'event' => $log['event'],
        'context' => $context,
    ];
}, $rawAuditLogs)));

function passless_format_datetime(?string $value): string {
    if ($value === null) {
        return '—';
    }

    return htmlspecialchars((new DateTimeImmutable($value))->format('Y-m-d H:i:s \U\T\C'), ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8');
}

?>
<!DOCTYPE html>
<html lang="en">

<head>
    <meta charset="UTF-8">
    <meta http-equiv="Content-Type" content="text/html; charset=utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Passless &mdash; Account</title>
    <link rel="stylesheet" href="/assets/style.css">
</head>

<body>
    <header class="site-header">
        <div class="container header-flex">
            <div>
                <h1>Your Passless account</h1>
                <p class="tagline">Manage your sessions and security.</p>
            </div>
            <nav class="header-nav">
                <?php if ($session->isAdmin()): ?>
                    <a class="btn" href="/admin.php">Security console</a>
                <?php endif; ?>
                <a class="btn" href="/">Request link</a>
            </nav>
        </div>
    </header>
    <main class="container">
        <?php if ($flash): ?>
            <div class="alert <?= htmlspecialchars($flash['type'], ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8') ?>">
                <?= htmlspecialchars($flash['message'], ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8') ?>
            </div>
        <?php endif; ?>

        <section class="card success">
            <h2>Signed in as</h2>
            <p><strong><?= htmlspecialchars($user['email'], ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8') ?></strong></p>
            <p class="muted">Session started <?= htmlspecialchars($session->issuedAt()->format('Y-m-d H:i:s \U\T\C'), ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8') ?>.</p>
            <div class="actions">
                <form method="post" action="/auth/logout.php" class="inline-form">
                    <input type="hidden" name="csrf_token" value="<?= htmlspecialchars($csrfToken, ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8') ?>">
                    <button type="submit" class="btn danger">Log out</button>
                </form>
            </div>
        </section>

        <section class="card" id="devices">
            <h2>Active sessions</h2>
            <?php if (empty($activeSessions)): ?>
                <p>No other active sessions.</p>
            <?php else: ?>
                <div class="table-responsive">
                    <table class="table">
                        <thead>
                            <tr>
                                <th scope="col">Device</th>
                                <th scope="col">IP address</th>
                                <th scope="col">Last active</th>
                                <th scope="col">Expires</th>
                                <th scope="col" class="actions">Actions</th>
                            </tr>
                        </thead>
                        <tbody>
                            <?php foreach ($activeSessions as $active): ?>
                                <?php
                                $isCurrent = hash_equals($currentSessionId, (string) $active['id']);
                                $expiresLabel = passless_format_datetime($active['expires_at']);
                                $absoluteDisplay = $active['absolute_expires_at'] !== null
                                    ? (new DateTimeImmutable((string) $active['absolute_expires_at']))->format('Y-m-d H:i:s \U\T\C')
                                    : null;
                                $expiresTitle = $absoluteDisplay
                                    ? ' title="' . htmlspecialchars('Absolute limit ' . $absoluteDisplay, ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8') . '"'
                                    : '';
                                ?>
                                <tr class="<?= $isCurrent ? 'current-session' : '' ?>">
                                    <td data-label="Device"><?= htmlspecialchars((string) $active['user_agent'], ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8') ?></td>
                                    <td data-label="IP address"><?= htmlspecialchars((string) $active['ip_address'], ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8') ?></td>
                                    <td data-label="Last active"><?= passless_format_datetime((string) $active['updated_at']); ?></td>
                                    <td data-label="Expires" <?= $expiresTitle ?>><?= $expiresLabel; ?></td>
                                    <td class="actions" data-label="Actions">
                                        <?php if ($isCurrent): ?>
                                            <span class="muted">Current session</span>
                                        <?php else: ?>
                                            <form method="post" action="/auth/revoke.php" class="inline-form">
                                                <input type="hidden" name="csrf_token" value="<?= htmlspecialchars($csrfToken, ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8') ?>">
                                                <input type="hidden" name="session_id" value="<?= htmlspecialchars((string) $active['id'], ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8') ?>">
                                                <button type="submit" class="btn danger">Revoke</button>
                                            </form>
                                        <?php endif; ?>
                                    </td>
                                </tr>
                            <?php endforeach; ?>
                        </tbody>
                    </table>
                </div>
            <?php endif; ?>
        </section>

        <section class="card" id="security">
            <h2>Security activity</h2>
            <?php if (empty($securityEvents)): ?>
                <p>No recent security events for your account.</p>
            <?php else: ?>
                <ul class="timeline">
                    <?php foreach ($securityEvents as $event): ?>
                        <li>
                            <div class="timeline-time"><?= htmlspecialchars((string) $event['time'], ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8') ?></div>
                            <div class="timeline-body">
                                <strong><?= htmlspecialchars((string) $event['type'], ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8') ?></strong>
                                <pre class="mini-json"><?= htmlspecialchars(json_encode($event['context'], JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES), ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8') ?></pre>
                            </div>
                        </li>
                    <?php endforeach; ?>
                </ul>
            <?php endif; ?>
        </section>

        <section class="card" id="audit">
            <h2>Audit trail</h2>
            <?php if (empty($auditLogs)): ?>
                <p>No audit entries recorded for your account yet.</p>
            <?php else: ?>
                <div class="table-responsive">
                    <table class="table">
                        <thead>
                            <tr>
                                <th scope="col">Time (UTC)</th>
                                <th scope="col">Event</th>
                                <th scope="col">Details</th>
                            </tr>
                        </thead>
                        <tbody>
                            <?php foreach ($auditLogs as $log): ?>
                                <tr>
                                    <td><?= htmlspecialchars((string) $log['time'], ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8') ?></td>
                                    <td><?= htmlspecialchars((string) $log['event'], ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8') ?></td>
                                    <td>
                                        <pre class="mini-json"><?= htmlspecialchars(json_encode($log['context'], JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES), ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8') ?></pre>
                                    </td>
                                </tr>
                            <?php endforeach; ?>
                        </tbody>
                    </table>
                </div>
            <?php endif; ?>
        </section>
    </main>
    <footer class="site-footer">
        <div class="container">
            <p>&copy; <?= date('Y') ?> Passless. Built for secure, passwordless authentication.</p>
        </div>
    </footer>
</body>

</html>
