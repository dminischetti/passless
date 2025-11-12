<?php

declare(strict_types=1);

require __DIR__ . '/../lib/bootstrap.php';

use Passless\Security\Csrf;
use Passless\Security\SessionAuth;
use Passless\Support\Log;
use Passless\Support\SecurityEventLogger;

$session = SessionAuth::instance();

if (($_SERVER['REQUEST_METHOD'] ?? 'GET') !== 'POST') {
    http_response_code(405);
    exit('Method Not Allowed');
}

if (!Csrf::validate($_POST['csrf_token'] ?? null)) {
    usleep(random_int(50000, 150000));
    $session->flash('error', 'Invalid request token.');
    passless_redirect('app.php');
}

$targetId = (string) ($_POST['session_id'] ?? '');
if ($targetId === '') {
    usleep(random_int(50000, 150000));
    $session->flash('error', 'Session identifier is required.');
    passless_redirect('app.php');
}

$currentUser = $session->currentUser();
if ($currentUser === null) {
    $session->flash('error', 'Please sign in again.');
    passless_redirect();
}

$revoked = $session->revokeSession($targetId);

if ($revoked) {
    Log::info('Session revoked by user', ['user_id' => $currentUser['id'], 'session_id' => $targetId]);
    SecurityEventLogger::record('session.revoked', ['user_id' => $currentUser['id'], 'session_id' => $targetId]);
    $session->flash('success', 'Session revoked successfully.');
} else {
    usleep(random_int(50000, 150000));
    $session->flash('error', 'Unable to revoke the selected session.');
}

passless_redirect('app.php');
