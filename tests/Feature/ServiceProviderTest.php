<?php

declare(strict_types=1);

use Illuminate\Support\Facades\Route;
use Illuminate\Support\ServiceProvider;
use Marcohern\Jwtauthorize\JwtauthorizeServiceProvider;
use Marcohern\Jwtauthorize\Middleware\Authorize;

it('registers the jwta middleware alias', function () {
    expect(Route::getMiddleware())->toHaveKey('jwta', Authorize::class);
});

it('publishes only the config file', function () {
    $paths = ServiceProvider::pathsToPublish(JwtauthorizeServiceProvider::class, 'jwtauthorize');

    expect($paths)->toHaveCount(1);
    expect(array_values($paths))->toBe([config_path('jwtauthorize.php')]);
});

it('merges the default role storage config', function () {
    expect(config('jwtauthorize.roles'))->toBe(['disk' => 'local', 'path' => 'jwta/roles']);
});
