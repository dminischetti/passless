<?php

declare(strict_types=1);

namespace Passless\Security;

final class Captcha
{
    private const REQUIRED_KEY = 'captcha_required';
    private const ANSWER_KEY = 'captcha_answers';

    public static function requireChallenge(string $scope): void
    {
        $_SESSION[self::REQUIRED_KEY][$scope] = true;
    }

    public static function clearRequirement(string $scope): void
    {
        unset($_SESSION[self::REQUIRED_KEY][$scope], $_SESSION[self::ANSWER_KEY][$scope]);
    }

    public static function isRequired(string $scope): bool
    {
        return !empty($_SESSION[self::REQUIRED_KEY][$scope]);
    }

    public static function generate(string $scope): array
    {
        $a = random_int(2, 9);
        $b = random_int(2, 9);
        $answer = (string) ($a + $b);
        $token = bin2hex(random_bytes(16));
        $_SESSION[self::ANSWER_KEY][$scope] = [
            'hash' => hash('sha256', $answer . '|' . $token),
            'token' => $token,
        ];

        return [
            'question' => sprintf('What is %d + %d?', $a, $b),
            'token' => $token,
        ];
    }

    public static function validate(string $scope, ?string $answer, ?string $token): bool
    {
        if (!isset($_SESSION[self::ANSWER_KEY][$scope])) {
            return false;
        }

        $data = $_SESSION[self::ANSWER_KEY][$scope];
        if (!is_array($data) || !isset($data['hash'], $data['token'])) {
            return false;
        }

        if (!is_string($answer) || !is_string($token) || !hash_equals($data['token'], $token)) {
            return false;
        }

        $valid = hash_equals($data['hash'], hash('sha256', trim($answer) . '|' . $token));

        if ($valid) {
            self::clearRequirement($scope);
        }

        return $valid;
    }
}
