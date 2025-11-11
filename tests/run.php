<?php

declare(strict_types=1);

require __DIR__ . '/bootstrap.php';
require __DIR__ . '/TokenServiceTest.php';
require __DIR__ . '/RateLimiterTest.php';
require __DIR__ . '/CsrfTest.php';
require __DIR__ . '/AuthFlowTest.php';

$passed = 0;
$failed = 0;
$messages = [];

foreach ($GLOBALS['TESTS'] as [$name, $test]) {
    try {
        $test();
        $passed++;
        $messages[] = sprintf('[PASS] %s', $name);
    } catch (\Throwable $exception) {
        $failed++;
        $messages[] = sprintf('[FAIL] %s: %s', $name, $exception->getMessage());
    }
}

echo implode(PHP_EOL, $messages) . PHP_EOL;
echo sprintf('Summary: %d passed, %d failed', $passed, $failed) . PHP_EOL;

exit($failed === 0 ? 0 : 1);
