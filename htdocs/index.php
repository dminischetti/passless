<?php

declare(strict_types=1);

require __DIR__ . '/lib/bootstrap.php';

use Passless\Security\Captcha;
use Passless\Security\Csrf;
use Passless\Security\SessionAuth;

$session = SessionAuth::instance();
$user = $session->currentUser();
$csrfToken = Csrf::token();
$devMode = passless_env('APP_ENV', 'production') === 'development';
$flash = $_SESSION['flash'] ?? null;
unset($_SESSION['flash']);
$resendAvailableAt = $_SESSION['resend_available_at'] ?? null;
$captchaScope = $_SESSION['active_captcha_scope'] ?? null;
$captchaChallenge = null;
if (is_string($captchaScope) && Captcha::isRequired($captchaScope)) {
    $captchaChallenge = Captcha::generate($captchaScope);
}
if ($resendAvailableAt !== null) {
    $resendAvailableAt = (int) $resendAvailableAt;
    if ($resendAvailableAt <= time()) {
        $resendAvailableAt = null;
        unset($_SESSION['resend_available_at']);
    }
}

?>
<!DOCTYPE html>
<html lang="en">

<head>
    <meta charset="UTF-8">
    <meta http-equiv="Content-Type" content="text/html; charset=utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Passless &mdash; Passwordless Authentication Demo</title>
    <link rel="stylesheet" href="assets/style.css">
</head>

<body>
    <header class="site-header">
        <div class="container">
            <h1>Passless</h1>
            <p class="tagline">Secure passwordless authentication with magic links.</p>
        </div>
    </header>
    <main class="container">
        <?php if ($flash): ?>
            <div class="alert <?= htmlspecialchars($flash['type'], ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8') ?>">
                <?= htmlspecialchars($flash['message'], ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8') ?>
            </div>
        <?php endif; ?>

        <?php if ($user !== null): ?>
            <section class="card success">
                <h2>Welcome back</h2>
                <p>You are signed in as <strong><?= htmlspecialchars($user['email'], ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8') ?></strong>.</p>
                <p class="muted">Session issued at <?= htmlspecialchars($session->issuedAt()->format('Y-m-d H:i:s'), ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8') ?> UTC.</p>
                <form method="post" action="auth/logout.php">
                    <input type="hidden" name="csrf_token" value="<?= htmlspecialchars($csrfToken, ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8') ?>">
                    <button type="submit" class="btn">Log out</button>
                </form>
            </section>
        <?php else: ?>
            <section class="card">
                <h2>Email login</h2>
                <p>Enter your email address and we will send you a secure magic link.</p>
                <form method="post" action="auth/request.php" class="form-stack">
                    <label for="email">Email address</label>
                    <input type="email" name="email" id="email" placeholder="you@example.com" required>
                    <input type="hidden" name="csrf_token" value="<?= htmlspecialchars($csrfToken, ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8') ?>">
                    <?php if ($captchaChallenge): ?>
                        <label for="captcha_answer"><?= htmlspecialchars($captchaChallenge['question'], ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8') ?></label>
                        <input type="text" name="captcha_answer" id="captcha_answer" autocomplete="off" inputmode="numeric" pattern="[0-9]+" required>
                        <input type="hidden" name="captcha_token" value="<?= htmlspecialchars($captchaChallenge['token'], ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8') ?>">
                    <?php endif; ?>
                    <button type="submit" class="btn primary">Send magic link</button>
                </form>
                <?php if ($resendAvailableAt): ?>
                    <span class="resend-hint">Rate limit window resets at <?= htmlspecialchars(gmdate('Y-m-d H:i:s \U\T\C', (int) $resendAvailableAt), ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8') ?>.</span>
                <?php endif; ?>
            </section>
        <?php endif; ?>

        <section class="card info">
            <h2>How it works</h2>
            <ul>
                <li>Rate limited requests prevent abuse.</li>
                <li>Magic link tokens are single-use and hashed at rest.</li>
                <li>Sessions are stored in MySQL with secure cookies.</li>
                <li>All POST requests are protected with CSRF tokens.</li>
            </ul>
        </section>

        <?php if ($devMode && isset($_SESSION['last_magic_link'])): ?>
            <section class="card warning">
                <h2>Development mode</h2>
                <p>The latest magic link generated for <code><?= htmlspecialchars($_SESSION['last_magic_link']['email'], ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8') ?></code>:</p>
                <p><a href="<?= htmlspecialchars($_SESSION['last_magic_link']['url'], ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8') ?>">Click to sign in</a></p>
                <p class="muted">Never display tokens outside of development.</p>
            </section>
        <?php endif; ?>
    </main>
    <footer class="site-footer">
        <div class="container">
            <p>&copy; <?= date('Y') ?> Passless. Built for secure, passwordless authentication.</p>
        </div>
    </footer>
</body>

</html>
