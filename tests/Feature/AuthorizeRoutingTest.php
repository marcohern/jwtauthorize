<?php

declare(strict_types=1);

use Illuminate\Support\Facades\Auth;
use Illuminate\Support\Facades\Route;
use Marcohern\Jwtauthorize\Facades\Jwtauthorize;
use PHPOpenSourceSaver\JWTAuth\JWTGuard;
use PHPOpenSourceSaver\JWTAuth\Payload;

/**
 * Fake an authenticated JWT whose `scope` claim holds the given policies.
 */
function fakeRoutedJwtScope(array|null $scope, bool $authenticated = true): void
{
    $payload = Mockery::mock(Payload::class);
    $payload->shouldReceive('get')->with('scope')->andReturn($scope);

    $guard = Mockery::mock(JWTGuard::class);
    $guard->shouldReceive('check')->andReturn($authenticated);
    $guard->shouldReceive('payload')->andReturn($payload);

    Auth::shouldReceive('guard')->andReturn($guard);
}

beforeEach(function () {
    Route::middleware(Jwtauthorize::middleware())->group(function () {
        Route::get('/admin/users', fn () => 'admin');
        Route::get('/public/page', fn () => 'public');
    });
});

it('lets allowed requests reach the route', function () {
    fakeRoutedJwtScope(['allow * /.*/' => ['deny * /\/admin(\/.*)?/']]);

    $this->get('/public/page')->assertOk()->assertSee('public');
});

it('responds 403 when the request is denied', function (string $uri) {
    fakeRoutedJwtScope(['allow * /.*/' => ['deny * /\/admin(\/.*)?/']]);

    $this->get($uri)->assertForbidden();
})->with([
    'plain path'   => ['/admin/users'],
    'encoded path' => ['/%61dmin/users'],
]);

it('responds 403 when the scope is malformed', function () {
    fakeRoutedJwtScope(['allow PUST /.*/']);

    $this->get('/public/page')->assertForbidden();
});

it('responds 401 when the request is not authenticated', function () {
    fakeRoutedJwtScope(null, authenticated: false);

    $this->get('/public/page')->assertUnauthorized()->assertHeader('WWW-Authenticate', 'Bearer');
});
