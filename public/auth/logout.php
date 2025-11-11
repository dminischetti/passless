<?php

declare(strict_types=1);

require __DIR__ . '/../../lib/bootstrap.php';

use Passless\Security\Csrf;
use Passless\Security\SessionAuth;

$session = SessionAuth::instance();

if (($_SERVER['REQUEST_METHOD'] ?? 'GET') !== 'POST') {
    http_response_code(405);
    exit('Method Not Allowed');
}

if (!Csrf::validate($_POST['csrf_token'] ?? null)) {
    $session->flash('error', 'Invalid request.');
    header('Location: /');
    exit;
}

$session->logOut();
$session->flash('success', 'You have been signed out.');
header('Location: /');
exit;
