<?php

declare(strict_types=1);

use Marcohern\Jwtauthorize\Facades\Jwtauthorize;
use Marcohern\Jwtauthorize\Middleware\Authorize;

it('resolves the package singleton through the facade', function () {
    expect(Jwtauthorize::getFacadeRoot())->toBe(app(Marcohern\Jwtauthorize\Jwtauthorize::class));
});

it('returns the authorize middleware class', function () {
    expect(Jwtauthorize::middleware())->toBe(Authorize::class);
});

it('returns a middleware the container can build', function () {
    expect(app(Jwtauthorize::middleware()))->toBeInstanceOf(Authorize::class);
});
