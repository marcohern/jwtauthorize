<?php

declare(strict_types=1);

use Illuminate\Support\Facades\Gate;
use Illuminate\Support\Facades\Route;
use Illuminate\Support\ServiceProvider;
use Marcohern\Jwtauthorize\JwtauthorizeServiceProvider;
use Marcohern\Jwtauthorize\Middleware\Authorize;

it('registers the jwta middleware alias', function () {
    expect(Route::getMiddleware())->toHaveKey('jwta', Authorize::class);
});

it('publishes the config file and the views', function () {
    $paths = ServiceProvider::pathsToPublish(JwtauthorizeServiceProvider::class, 'jwtauthorize');

    expect(array_values($paths))->toBe([config_path('jwtauthorize.php'), resource_path('views/vendor/jwtauthorize')]);
});

it('merges the default role storage config', function () {
    expect(config('jwtauthorize.roles'))->toBe(['disk' => 'local', 'path' => 'jwta/roles']);
});

it('publishes the views', function () {
    $paths = ServiceProvider::pathsToPublish(JwtauthorizeServiceProvider::class, 'jwtauthorize-views');

    expect(array_values($paths))->toBe([resource_path('views/vendor/jwtauthorize')]);
});

it('does not register the role pages unless the UI is enabled', function () {
    expect(Route::has('jwtauthorize.roles.index'))->toBeFalse();
    $this->get('/jwta/roles')->assertNotFound();
});

it('only opens the default manage gate in the local environment', function () {
    expect(Gate::allows('jwtauthorize.manage'))->toBeFalse();

    app()->detectEnvironment(fn () => 'local');

    expect(Gate::allows('jwtauthorize.manage'))->toBeTrue();
});
