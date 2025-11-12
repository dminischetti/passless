<?php

declare(strict_types=1);

require __DIR__ . '/lib/bootstrap.php';

use Passless\DB\Connector;
use Passless\Security\Csrf;
use Passless\Security\SessionAuth;

$session = SessionAuth::instance();
$user = $session->currentUser();
if ($user === null) {
    passless_redirect();
}

if (!$session->isAdmin()) {
    http_response_code(403);
    exit('Forbidden');
}

$csrfToken = Csrf::token();
$flash = $_SESSION['flash'] ?? null;
unset($_SESSION['flash']);

$pdo = Connector::connection();

$counts = [
    'users' => (int) $pdo->query('SELECT COUNT(*) FROM users')->fetchColumn(),
    'sessions' => (int) $pdo->query('SELECT COUNT(*) FROM sessions')->fetchColumn(),
    'tokens' => (int) $pdo->query('SELECT COUNT(*) FROM login_tokens')->fetchColumn(),
];

$rateLimitStatement = $pdo->prepare('SELECT COUNT(*) FROM security_events WHERE event_type LIKE :pattern');
$rateLimitStatement->execute([':pattern' => 'rate_limit%']);
$counts['rate_limits'] = (int) $rateLimitStatement->fetchColumn();

$lockStatement = $pdo->prepare('SELECT COUNT(*) FROM users WHERE locked_until IS NOT NULL AND locked_until > :now');
$lockStatement->execute([':now' => (new DateTimeImmutable('now'))->format('Y-m-d H:i:s')]);
$counts['lockouts'] = (int) $lockStatement->fetchColumn();

$securityEvents = $pdo->query('SELECT event_type, context, created_at FROM security_events ORDER BY created_at DESC LIMIT 50')->fetchAll() ?: [];
$auditLogs = $pdo->query('SELECT event, context, created_at FROM audit_logs ORDER BY created_at DESC LIMIT 50')->fetchAll() ?: [];

function passless_decode_context(?string $context): array {
    if ($context === null || $context === '') {
        return [];
    }

    $decoded = json_decode($context, true);
    return is_array($decoded) ? $decoded : ['raw' => $context];
}

?>
<!DOCTYPE html>
<html lang="en">

<head>
    <meta charset="UTF-8">
    <meta http-equiv="Content-Type" content="text/html; charset=utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Passless &mdash; Security console</title>
    <link rel="stylesheet" href="<?= htmlspecialchars(passless_path('assets/style.css'), ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8') ?>">
</head>

<body>
    <header class="site-header">
        <div class="container header-flex">
            <div>
                <h1>Security console</h1>
                <p class="tagline">Monitor audit trails and suspicious activity.</p>
            </div>
            <nav class="header-nav">
                <a class="btn" href="<?= htmlspecialchars(passless_path('app.php'), ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8') ?>">Account</a>
                <form method="post" action="<?= htmlspecialchars(passless_path('auth/logout.php'), ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8') ?>" class="inline-form">
                    <input type="hidden" name="csrf_token" value="<?= htmlspecialchars($csrfToken, ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8') ?>">
                    <button type="submit" class="btn danger">Log out</button>
                </form>
            </nav>
        </div>
    </header>
    <main class="container">
        <?php if ($flash): ?>
            <div class="alert <?= htmlspecialchars($flash['type'], ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8') ?>">
                <?= htmlspecialchars($flash['message'], ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8') ?>
            </div>
        <?php endif; ?>

        <section class="card stats">
            <h2>System health</h2>
            <div class="stats-grid">
                <div class="stat">
                    <span class="stat-value"><?= htmlspecialchars((string) $counts['users'], ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8') ?></span>
                    <span class="stat-label">Registered users</span>
                </div>
                <div class="stat">
                    <span class="stat-value"><?= htmlspecialchars((string) $counts['sessions'], ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8') ?></span>
                    <span class="stat-label">Active sessions</span>
                </div>
                <div class="stat">
                    <span class="stat-value"><?= htmlspecialchars((string) $counts['tokens'], ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8') ?></span>
                    <span class="stat-label">Open magic links</span>
                </div>
                <div class="stat">
                    <span class="stat-value"><?= htmlspecialchars((string) $counts['rate_limits'], ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8') ?></span>
                    <span class="stat-label">Rate-limit hits</span>
                </div>
                <div class="stat">
                    <span class="stat-value"><?= htmlspecialchars((string) $counts['lockouts'], ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8') ?></span>
                    <span class="stat-label">Active lockouts</span>
                </div>
            </div>
        </section>

        <section class="card">
            <h2>Recent security events</h2>
            <div class="table-responsive">
                <table class="table">
                    <thead>
                        <tr>
                            <th scope="col">Time (UTC)</th>
                            <th scope="col">Type</th>
                            <th scope="col">Context</th>
                        </tr>
                    </thead>
                    <tbody>
                        <?php if (empty($securityEvents)): ?>
                            <tr>
                                <td colspan="3">No security events logged.</td>
                            </tr>
                        <?php else: ?>
                            <?php foreach ($securityEvents as $event): ?>
                                <?php $context = passless_decode_context($event['context'] ?? null); ?>
                                <tr>
                                    <td><?= htmlspecialchars((string) $event['created_at'], ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8') ?></td>
                                    <td><?= htmlspecialchars((string) $event['event_type'], ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8') ?></td>
                                    <td>
                                        <pre class="mini-json"><?= htmlspecialchars(json_encode($context, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES), ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8') ?></pre>
                                    </td>
                                </tr>
                            <?php endforeach; ?>
                        <?php endif; ?>
                    </tbody>
                </table>
            </div>
        </section>

        <section class="card">
            <h2>Audit log</h2>
            <div class="table-responsive">
                <table class="table">
                    <thead>
                        <tr>
                            <th scope="col">Time (UTC)</th>
                            <th scope="col">Event</th>
                            <th scope="col">Payload</th>
                        </tr>
                    </thead>
                    <tbody>
                        <?php if (empty($auditLogs)): ?>
                            <tr>
                                <td colspan="3">No audit entries available.</td>
                            </tr>
                        <?php else: ?>
                            <?php foreach ($auditLogs as $log): ?>
                                <?php $context = passless_decode_context($log['context'] ?? null); ?>
                                <tr>
                                    <td><?= htmlspecialchars((string) $log['created_at'], ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8') ?></td>
                                    <td><?= htmlspecialchars((string) $log['event'], ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8') ?></td>
                                    <td>
                                        <pre class="mini-json"><?= htmlspecialchars(json_encode($context, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES), ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8') ?></pre>
                                    </td>
                                </tr>
                            <?php endforeach; ?>
                        <?php endif; ?>
                    </tbody>
                </table>
            </div>
        </section>
    </main>
    <footer class="site-footer">
        <div class="container">
            <p>&copy; <?= date('Y') ?> Passless. Passwordless authentication demo.</p>
        </div>
    </footer>
</body>

</html>
