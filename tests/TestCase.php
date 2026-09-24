<?php

declare(strict_types=1);

namespace Marcohern\Jwtauthorize\Tests;

use Marcohern\Jwtauthorize\JwtauthorizeServiceProvider;
use Orchestra\Testbench\TestCase as Orchestra;

abstract class TestCase extends Orchestra
{
    protected function getPackageProviders($app): array
    {
        return [
            JwtauthorizeServiceProvider::class,
        ];
    }
}
