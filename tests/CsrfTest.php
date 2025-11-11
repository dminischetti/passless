<?php

declare(strict_types=1);

use Passless\Security\Csrf;

register_test('CSRF tokens validate and rotate', function (): void {
    passless_test_reset();
    $token = Csrf::token();
    assertTrue(is_string($token) && strlen($token) > 10, 'Token should be generated.');
    assertTrue(Csrf::validate($token), 'Token should validate.');

    Csrf::rotate();
    $newToken = Csrf::token();
    assertTrue($newToken !== $token, 'Token should change after rotation.');
    assertTrue(!Csrf::validate($token), 'Old token should no longer validate.');
    assertTrue(Csrf::validate($newToken), 'New token should validate.');
});
