<?php

declare(strict_types=1);

namespace Passless\Mail\Templates;

use DateTimeImmutable;

final class MagicLinkTemplate
{
    public static function renderText(string $link, DateTimeImmutable $expiresAt): string
    {
        $expires = $expiresAt->format('Y-m-d H:i:s \U\T\C');
        return <<<TEXT
You requested a secure magic link to access Passless.

Use this link to sign in: {$link}
It expires at {$expires}.

If you did not request this email you can ignore it.
TEXT;
    }

    public static function renderHtml(string $link, DateTimeImmutable $expiresAt): string
    {
        $escapedLink = htmlspecialchars($link, ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8');
        $expires = htmlspecialchars($expiresAt->format('Y-m-d H:i:s \U\T\C'), ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8');

        return <<<HTML
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>Your Passless magic link</title>
</head>
<body style="font-family: Arial, sans-serif; color: #1f2933; background: #f5f7fa; padding: 24px;">
    <table role="presentation" width="100%" cellspacing="0" cellpadding="0" style="max-width: 600px; margin: auto; background: #ffffff; border-radius: 12px; padding: 32px; box-shadow: 0 12px 24px rgba(31,41,51,0.08);">
        <tr><td style="text-align: center;">
            <h1 style="margin-bottom: 16px; color: #075985;">Sign in to Passless</h1>
            <p style="margin-bottom: 24px; font-size: 16px;">Click the secure button below to complete your login. This magic link expires at {$expires}.</p>
            <p style="margin-bottom: 32px;"><a href="{$escapedLink}" style="display: inline-block; padding: 12px 24px; background: #2563eb; color: #ffffff; text-decoration: none; border-radius: 999px; font-weight: bold;">Sign in</a></p>
            <p style="font-size: 14px; color: #52606d;">If the button does not work, copy and paste this link into your browser:</p>
            <p style="word-break: break-all; font-size: 14px;"><a href="{$escapedLink}" style="color: #2563eb;">{$escapedLink}</a></p>
            <p style="margin-top: 24px; font-size: 14px; color: #9aa5b1;">You are receiving this email because someone attempted to sign in with your address. If this was not you, we recommend deleting this email.</p>
        </td></tr>
    </table>
</body>
</html>
HTML;
    }
}
