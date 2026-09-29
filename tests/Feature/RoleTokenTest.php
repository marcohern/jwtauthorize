<?php

declare(strict_types=1);

use Illuminate\Foundation\Testing\RefreshDatabase;
use Illuminate\Support\Facades\Route;
use Illuminate\Support\Facades\Storage;
use Marcohern\Jwtauthorize\PolicyBuilder;
use Marcohern\Jwtauthorize\PolicyManager;
use Marcohern\Jwtauthorize\Tests\Fixtures\JwtUser;
use PHPOpenSourceSaver\JWTAuth\Providers\LaravelServiceProvider;

uses(RefreshDatabase::class);

/**
 * Issue a real, signed token whose `scope` claim holds the given roles' policies.
 */
function issueRoleToken(string ...$roles): string
{
    $user = JwtUser::create(['name' => 'Ada', 'email' => 'ada@example.com', 'password' => 'secret']);

    return auth('api')->claims(['scope' => app(PolicyManager::class)->claim(...$roles)])->login($user);
}

beforeEach(function () {
    $this->loadLaravelMigrations();
    $this->app->register(LaravelServiceProvider::class);
    config([
        'jwt.secret' => str_repeat('s', 64),
        'auth.guards.api' => ['driver' => 'jwt', 'provider' => 'users'],
        'auth.providers.users.model' => JwtUser::class,
        'jwtauthorize.guard' => 'api',
    ]);
    Storage::fake('local');

    $builder = app(PolicyBuilder::class);
    $manager = app(PolicyManager::class);
    $manager->create('reader', $builder->fromList(['allow GET /.*/']));
    $manager->create('no-admin', $builder->fromList([
        'deny * /\/admin(\/.*)?/' => ['allow GET /\/admin\/reports/'],
    ]));

    Route::middleware('jwta')->group(function () {
        Route::get('/posts', fn () => 'posts');
        Route::post('/posts', fn () => 'created');
        Route::get('/admin/users', fn () => 'admin');
        Route::get('/admin/reports', fn () => 'reports');
    });
});

it('authorizes a real token carrying role policies', function (string $method, string $uri, int $status) {
    $token = issueRoleToken('reader', 'no-admin');

    $this->withToken($token)->json($method, $uri)->assertStatus($status);
})->with([
    'allowed read' => ['GET', '/posts', 200],
    'head covered by get' => ['HEAD', '/posts', 200],
    'method not in any role' => ['POST', '/posts', 403],
    'denied by another role' => ['GET', '/admin/users', 403],
    'allowed by a child rule' => ['GET', '/admin/reports', 200],
]);

it('rejects requests without a token', function () {
    $this->getJson('/posts')->assertUnauthorized();
});
