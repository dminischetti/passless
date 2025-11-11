<?php

declare(strict_types=1);

namespace Passless\Mail;

use DateTimeImmutable;
use Passless\Mail\Templates\MagicLinkTemplate;
use Passless\Support\Exception\MailTransportException;
use Passless\Support\Log;

final class Mailer
{
    public static function sendMagicLink(string $recipient, string $link, DateTimeImmutable $expiresAt): void
    {
        if (!self::boolEnv('MAIL_ENABLED', true)) {
            Log::info('Mail disabled, skipping delivery', ['email' => $recipient, 'link' => $link]);
            return;
        }

        $provider = strtolower((string) self::env('MAIL_PROVIDER', 'sendgrid'));
        $subject = self::env('MAIL_SUBJECT', 'Your Passless magic link');
        $text = MagicLinkTemplate::renderText($link, $expiresAt);
        $html = MagicLinkTemplate::renderHtml($link, $expiresAt);

        try {
            if ($provider === 'mailgun') {
                self::sendWithMailgun($recipient, $subject, $text, $html);
            } else {
                self::sendWithSendGrid($recipient, $subject, $text, $html);
            }
        } catch (MailTransportException $exception) {
            Log::error('Magic link email delivery failed', [
                'email' => $recipient,
                'provider' => $provider,
                'error' => $exception->getMessage(),
            ]);
            throw $exception;
        }
    }

    public static function sendSecurityAlert(string $recipient, string $subject, string $message): void
    {
        if (!self::boolEnv('MAIL_ENABLED', true)) {
            return;
        }

        $provider = strtolower((string) self::env('MAIL_PROVIDER', 'sendgrid'));
        $html = '<p>' . htmlspecialchars($message, ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8') . '</p>';

        try {
            if ($provider === 'mailgun') {
                self::sendWithMailgun($recipient, $subject, $message, $html);
            } else {
                self::sendWithSendGrid($recipient, $subject, $message, $html);
            }
        } catch (MailTransportException $exception) {
            Log::warning('Security alert email delivery failed', [
                'email' => $recipient,
                'provider' => $provider,
                'error' => $exception->getMessage(),
            ]);
        }
    }

    private static function sendWithSendGrid(string $recipient, string $subject, string $text, string $html): void
    {
        $apiKey = self::env('SENDGRID_API_KEY');
        $from = self::env('MAIL_FROM', 'no-reply@example.com');
        if (!$apiKey) {
            throw new MailTransportException('Missing SENDGRID_API_KEY environment variable');
        }

        $payload = json_encode([
            'personalizations' => [[
                'to' => [['email' => $recipient]],
            ]],
            'from' => ['email' => $from],
            'subject' => $subject,
            'content' => [
                ['type' => 'text/plain', 'value' => $text],
                ['type' => 'text/html', 'value' => $html],
            ],
        ]);

        $ch = curl_init('https://api.sendgrid.com/v3/mail/send');
        curl_setopt_array($ch, [
            CURLOPT_HTTPHEADER => [
                'Authorization: Bearer ' . $apiKey,
                'Content-Type: application/json',
            ],
            CURLOPT_POST => true,
            CURLOPT_POSTFIELDS => $payload,
            CURLOPT_RETURNTRANSFER => true,
            CURLOPT_TIMEOUT => 15,
        ]);

        $response = curl_exec($ch);
        $status = curl_getinfo($ch, CURLINFO_RESPONSE_CODE);
        if ($response === false || $status >= 400) {
            $error = curl_error($ch);
            curl_close($ch);
            throw new MailTransportException('SendGrid responded with status ' . $status . ' ' . $error);
        }

        curl_close($ch);
    }

    private static function sendWithMailgun(string $recipient, string $subject, string $text, string $html): void
    {
        $apiKey = self::env('MAILGUN_API_KEY');
        $domain = self::env('MAILGUN_DOMAIN');
        $from = self::env('MAIL_FROM', 'no-reply@example.com');

        if (!$apiKey || !$domain) {
            throw new MailTransportException('Missing Mailgun configuration');
        }

        $ch = curl_init('https://api.mailgun.net/v3/' . $domain . '/messages');
        curl_setopt_array($ch, [
            CURLOPT_USERPWD => 'api:' . $apiKey,
            CURLOPT_POST => true,
            CURLOPT_POSTFIELDS => [
                'from' => $from,
                'to' => $recipient,
                'subject' => $subject,
                'text' => $text,
                'html' => $html,
            ],
            CURLOPT_RETURNTRANSFER => true,
            CURLOPT_TIMEOUT => 15,
        ]);

        $response = curl_exec($ch);
        $status = curl_getinfo($ch, CURLINFO_RESPONSE_CODE);
        if ($response === false || $status >= 400) {
            $error = curl_error($ch);
            curl_close($ch);
            throw new MailTransportException('Mailgun responded with status ' . $status . ' ' . $error);
        }

        curl_close($ch);
    }

    private static function env(string $key, ?string $default = null): ?string
    {
        return \passless_env($key, $default);
    }

    private static function boolEnv(string $key, bool $default = false): bool
    {
        $value = self::env($key);
        if ($value === null) {
            return $default;
        }

        return in_array(strtolower($value), ['1', 'true', 'yes', 'on'], true);
    }
}
