<?php

declare(strict_types=1);

namespace Jwtauthorize\Jwtauthorize\Tests;

use Jwtauthorize\Jwtauthorize\JwtauthorizeServiceProvider;
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
