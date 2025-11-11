<?php

declare(strict_types=1);

use Passless\Security\RateLimiter;

register_test('RateLimiter enforces limits', function (): void {
    passless_test_reset();
    $result1 = RateLimiter::hit('login', 'tester', 2, 60);
    assertTrue(!$result1->limited(), 'First attempt should not be limited.');
    $result2 = RateLimiter::hit('login', 'tester', 2, 60);
    assertTrue(!$result2->limited(), 'Second attempt should not be limited.');
    $result3 = RateLimiter::hit('login', 'tester', 2, 60);
    assertTrue($result3->limited(), 'Third attempt should trigger limit.');
});

register_test('RateLimiter clear removes counters', function (): void {
    passless_test_reset();
    RateLimiter::hit('api', 'client', 1, 60);
    RateLimiter::clear('api', 'client');
    $result = RateLimiter::hit('api', 'client', 1, 60);
    assertTrue(!$result->limited(), 'Counter should be reset after clear.');
});
