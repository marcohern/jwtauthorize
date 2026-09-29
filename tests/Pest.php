<?php

declare(strict_types=1);

use Marcohern\Jwtauthorize\Tests\TestCase;
use Marcohern\Jwtauthorize\Tests\UiTestCase;

/*
 * Give each parallel worker its own service and package manifests. They are
 * otherwise shared in the Testbench skeleton, and workers rebuilding them at
 * the same time fail on Windows ("access denied" on rename).
 */
$worker = $_SERVER['TEST_TOKEN'] ?? getenv('TEST_TOKEN') ?: 'serial';
foreach (['APP_SERVICES_CACHE' => 'services', 'APP_PACKAGES_CACHE' => 'packages'] as $variable => $manifest) {
    $path = "bootstrap/cache/$manifest-$worker.php";
    $_ENV[$variable] = $_SERVER[$variable] = $path;
    putenv("$variable=$path");
}

uses(TestCase::class)->in('Feature', 'Unit', 'ArchTest.php');
uses(UiTestCase::class)->in('Ui');
