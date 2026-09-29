<?php

declare(strict_types=1);

use Illuminate\Http\Request;
use Illuminate\Support\Facades\Auth;
use Marcohern\Jwtauthorize\Exceptions\JwtaForbiddenException;
use Marcohern\Jwtauthorize\Exceptions\JwtaUnauthorizedException;
use Marcohern\Jwtauthorize\Middleware\Authorize;
use Marcohern\Jwtauthorize\Parser;
use Marcohern\Jwtauthorize\PolicyBuilder;
use PHPOpenSourceSaver\JWTAuth\JWTGuard;
use PHPOpenSourceSaver\JWTAuth\Payload;
use Symfony\Component\HttpFoundation\Response;

/**
 * Fake the JWT guard: authenticated or not, and the claims its token carries.
 *
 * @param  array<string, mixed>  $claims
 */
function fakeJwtGuard(array $claims = [], bool $authenticated = true): void
{
    $payload = Mockery::mock(Payload::class);
    $payload->shouldReceive('get')->andReturnUsing(fn (string $claim) => $claims[$claim] ?? null);

    $guard = Mockery::mock(JWTGuard::class);
    $guard->shouldReceive('check')->andReturn($authenticated);
    $guard->shouldReceive('payload')->andReturn($payload);

    Auth::shouldReceive('guard')->andReturn($guard);
}

/**
 * Fake an authenticated JWT whose `scope` claim holds the given value.
 */
function fakeJwtScope(mixed $scope): void
{
    fakeJwtGuard(['scope' => $scope]);
}

beforeEach(function () {
    $parser = new Parser;
    $this->middleware = new Authorize(new PolicyBuilder($parser), $parser);
    $this->next = fn (Request $request): Response => new Response('ok');
});

test('[Authorize::handle] lets allowed requests through', function (array $scope, string $method, string $uri) {
    fakeJwtScope($scope);

    $response = $this->middleware->handle(Request::create($uri, $method), $this->next);

    expect($response->getContent())->toBe('ok');
})->with([
    'allow everything' => [['allow * /.*/'], 'GET', '/anything'],
    'allow a specific method' => [['allow GET /\/users/'], 'GET', '/users'],
    'allow a method in a list' => [['allow GET,POST /\/users/'], 'POST', '/users'],
    'allow the root path' => [['allow GET /\//'], 'GET', '/'],
    'query string is ignored' => [['allow GET /\/users/'], 'GET', '/users?page=2'],
    'parent allows, no child' => [['allow * /.*/' => ['deny * /\/admin(\/.*)?/']], 'GET', '/users'],
    'child allows, parent denies' => [['deny * /.*/' => ['allow GET /\/public(\/.*)?/']], 'GET', '/public/page'],
    'sibling allows, other skips' => [['allow GET /\/users/', 'deny * /\/admin(\/.*)?/'], 'GET', '/users'],
]);

test('[Authorize::handle] denies requests not allowed by the scope', function (array $scope, string $method, string $uri) {
    fakeJwtScope($scope);

    $this->middleware->handle(Request::create($uri, $method), $this->next);
})->throws(JwtaForbiddenException::class, 'Access denied.')->with([
    'child denies' => [['allow * /.*/' => ['deny * /\/admin(\/.*)?/']], 'GET', '/admin/users'],
    'top level deny' => [['deny * /.*/'], 'GET', '/users'],
    'no policy matches uri' => [['allow GET /\/users/'], 'GET', '/orders'],
    'method does not match' => [['allow GET /.*/'], 'POST', '/users'],
    'rule matches whole path only' => [['allow GET /\/users/'], 'GET', '/users/1'],
]);

test('[Authorize::handle] cannot be bypassed', function (array $scope, string $method, string $uri) {
    fakeJwtScope($scope);

    $this->middleware->handle(Request::create($uri, $method), $this->next);
})->throws(JwtaForbiddenException::class, 'Access denied.')->with([
    'allowed path smuggled in the query' => [['deny * /.*/' => ['allow GET /\/public(\/.*)?/']], 'GET', '/admin/secret?x=/public'],
    'denied path url-encoded' => [['allow * /.*/' => ['deny * /\/admin(\/.*)?/']], 'GET', '/%61dmin/users'],
    'allowed path inside a longer path' => [['deny * /.*/' => ['allow GET /\/public/']], 'GET', '/admin/public'],
    'deny listed after an allow sibling' => [['allow * /.*/', 'deny * /\/admin(\/.*)?/'], 'GET', '/admin/users'],
    'method that is a substring' => [['allow GET /.*/'], 'GE', '/users'],
]);

test('[Authorize::handle] denies when a deny rule fails to evaluate', function () {
    $jit = ini_get('pcre.jit');
    $limit = ini_get('pcre.backtrack_limit');
    ini_set('pcre.jit', '0');
    ini_set('pcre.backtrack_limit', '100');

    try {
        // [bc] instead of b: PCRE skips a literal required character that is absent without backtracking
        fakeJwtScope(['allow * /.*/' => ['deny * /\/(a+)+[bc]/']]);
        $this->middleware->handle(Request::create('/'.str_repeat('a', 30), 'GET'), $this->next);
    } finally {
        ini_set('pcre.jit', $jit);
        ini_set('pcre.backtrack_limit', $limit);
    }
})->throws(JwtaForbiddenException::class, 'Access denied.');

test('[Authorize::handle] denies requests when the scope is empty or malformed', function (mixed $scope) {
    fakeJwtScope($scope);

    $this->middleware->handle(Request::create('/users', 'GET'), $this->next);
})->throws(JwtaForbiddenException::class, 'Access denied.')->with([
    'empty scope' => [[]],
    'missing scope' => [null],
    'oauth scope' => ['read write'],
    'invalid policy' => [['allow PUST /.*/']],
    'invalid regex' => [['allow GET /(/']],
    'unsupported type' => [[42]],
]);

test('[Authorize::handle] rejects unauthenticated requests', function () {
    fakeJwtGuard(authenticated: false);

    $this->middleware->handle(Request::create('/users', 'GET'), $this->next);
})->throws(JwtaUnauthorizedException::class);

test('[Authorize::handle] reads the claim and guard from config', function () {
    config(['jwtauthorize.claim' => 'jwta', 'jwtauthorize.guard' => 'api']);
    fakeJwtGuard(['scope' => ['deny * /.*/'], 'jwta' => ['allow * /.*/']]);

    $response = $this->middleware->handle(Request::create('/users', 'GET'), $this->next);

    expect($response->getContent())->toBe('ok');
    Auth::shouldHaveReceived('guard')->with('api');
});

test('[Authorize] exceptions carry HTTP status codes', function () {
    expect((new JwtaForbiddenException)->getStatusCode())->toBe(403);
    expect((new JwtaUnauthorizedException)->getStatusCode())->toBe(401);
    expect((new JwtaUnauthorizedException)->getHeaders())->toBe(['WWW-Authenticate' => 'Bearer']);
});
