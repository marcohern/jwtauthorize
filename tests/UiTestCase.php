<?php

declare(strict_types=1);

namespace Marcohern\Jwtauthorize\Tests;

use Illuminate\Support\Facades\Gate;

/**
 * Test case with the role management UI enabled, without the `auth`
 * middleware, and with the `jwtauthorize.manage` gate open to everyone.
 */
abstract class UiTestCase extends TestCase
{
    protected function defineEnvironment($app): void
    {
        $app['config']->set('app.key', 'base64:'.base64_encode(str_repeat('k', 32)));
        $app['config']->set('jwtauthorize.ui', ['enabled' => true, 'prefix' => 'jwta', 'middleware' => ['web']]);

        Gate::define('jwtauthorize.manage', fn (mixed $user = null): bool => true);
    }
}
