<?php

declare(strict_types=1);

use Illuminate\Http\Request;
use Illuminate\Support\Facades\Auth;
use Marcohern\Jwtauthorize\Exceptions\JwtaParserException;
use Marcohern\Jwtauthorize\Middleware\Authorize;
use Marcohern\Jwtauthorize\Parser;
use Marcohern\Jwtauthorize\PolicyBuilder;
use PHPOpenSourceSaver\JWTAuth\Payload;
use Symfony\Component\HttpFoundation\Response;

/**
 * Make auth()->payload()->get('scope') return the given scope.
 */
function fakeJwtScope(array|null $scope): void
{
  $payload = Mockery::mock(Payload::class);
  $payload->shouldReceive('get')->with('scope')->andReturn($scope);

  Auth::shouldReceive('payload')->andReturn($payload);
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
  'allow everything'           => [['allow * /.*/'], 'GET', '/anything'],
  'allow a specific method'    => [['allow GET /\/users/'], 'GET', '/users'],
  'parent allows, no child'    => [['allow * /.*/' => ['deny * /\/admin(\/.*)?/']], 'GET', '/users'],
  'child allows, parent denies'=> [['deny * /.*/' => ['allow GET /\/public(\/.*)?/']], 'GET', '/public/page'],
]);

test('[Authorize::handle] denies requests not allowed by the scope', function (array $scope, string $method, string $uri) {
  fakeJwtScope($scope);

  $this->middleware->handle(Request::create($uri, $method), $this->next);
})->throws(JwtaParserException::class, 'Access denied.')->with([
  'child denies'          => [['allow * /.*/' => ['deny * /\/admin(\/.*)?/']], 'GET', '/admin/users'],
  'top level deny'        => [['deny * /.*/'], 'GET', '/users'],
  'no policy matches uri' => [['allow GET /\/users/'], 'GET', '/orders'],
  'method does not match' => [['allow GET /.*/'], 'POST', '/users'],
]);

test('[Authorize::handle] denies requests when the scope is empty', function (array|null $scope) {
  fakeJwtScope($scope);

  $this->middleware->handle(Request::create('/users', 'GET'), $this->next);
})->throws(JwtaParserException::class, 'Access denied.')->with([
  'empty scope'   => [[]],
  'missing scope' => [null],
]);

test('[Authorize::handle] rejects scopes with invalid policies', function () {
  fakeJwtScope(['allow PUST /.*/']);

  $this->middleware->handle(Request::create('/users', 'GET'), $this->next);
})->throws(JwtaParserException::class, 'Policy invalid.');
