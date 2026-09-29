<?php

declare(strict_types=1);

use Illuminate\Support\Facades\Artisan;
use Illuminate\Support\Facades\File;
use Illuminate\Support\Facades\Storage;
use Marcohern\Jwtauthorize\Policy;
use Marcohern\Jwtauthorize\PolicyBuilder;
use Marcohern\Jwtauthorize\PolicyManager;

/**
 * Write a policy file for --file into the test's temp folder and return its path.
 */
function rolePolicyFile(string $json): string
{
    $path = test()->policyDir.'/policies.json';
    file_put_contents($path, $json);

    return $path;
}

beforeEach(function () {
    Storage::fake('local');
    $this->manager = app(PolicyManager::class);
    $this->policyDir = sys_get_temp_dir().'/jwta-'.uniqid();
    File::ensureDirectoryExists($this->policyDir);
});

afterEach(function () {
    File::deleteDirectory($this->policyDir);
});

it('creates a role from policy arguments', function () {
    $this->artisan('jwta:role:create', ['role' => 'viewer', 'policies' => ['allow GET /.*/', 'deny * /\/admin(\/.*)?/']])
        ->expectsOutput('Role [viewer] created.')
        ->assertSuccessful();

    expect($this->manager->get('viewer'))->toHaveCount(2);
});

it('creates a role with nested policies from a file', function () {
    $file = rolePolicyFile('{"0": "allow GET /.*/", "deny * /\\\\/admin(\\\\/.*)?/": ["allow GET /\\\\/admin\\\\/reports/"]}');

    $this->artisan('jwta:role:create', ['role' => 'editor', '--file' => $file])->assertSuccessful();

    $policies = $this->manager->get('editor');
    expect($policies)->toHaveCount(2);
    expect($policies[1]->pathex)->toBe('/\/admin(\/.*)?/');
    expect($policies[1]->children)->toHaveCount(1);
});

it('does not create a role that already exists', function () {
    $this->artisan('jwta:role:create', ['role' => 'viewer', 'policies' => ['allow GET /.*/']]);

    $this->artisan('jwta:role:create', ['role' => 'viewer', 'policies' => ['deny * /.*/']])
        ->expectsOutput('Role [viewer] already exists.')
        ->assertFailed();

    expect($this->manager->get('viewer')[0]->action)->toBe('allow');
});

it('does not create a role from invalid input', function (array $arguments, string $message) {
    $this->artisan('jwta:role:create', ['role' => 'viewer', ...$arguments])
        ->expectsOutputToContain($message)
        ->assertFailed();

    expect($this->manager->exists('viewer'))->toBeFalse();
})->with([
    'invalid policy' => [['policies' => ['allow PUST /.*/']], 'Policy invalid.'],
    'invalid regex' => [['policies' => ['allow GET /(/']], 'Path in policy invalid.'],
    'no policies' => [[], 'No policies given.'],
    'missing file' => [['--file' => 'missing-policies.json'], 'cannot be read'],
    'invalid role' => [['role' => '../etc', 'policies' => ['allow GET /.*/']], 'Role name [../etc] invalid.'],
]);

it('does not accept both policy arguments and a file', function () {
    $file = rolePolicyFile('["allow GET /.*/"]');

    $this->artisan('jwta:role:create', ['role' => 'viewer', 'policies' => ['allow GET /.*/'], '--file' => $file])
        ->expectsOutput('Pass policies as arguments or with --file, not both.')
        ->assertFailed();
});

it('does not create a role from a file that is not a policy list', function (string $json, string $message) {
    $file = rolePolicyFile($json);

    $this->artisan('jwta:role:create', ['role' => 'viewer', '--file' => $file])
        ->expectsOutputToContain($message)
        ->assertFailed();
})->with([
    'invalid json' => ['{not json', 'Syntax error'],
    'json string' => ['"allow GET /.*/"', 'must hold a JSON list or object'],
]);

it('updates the policies of a role', function () {
    $this->artisan('jwta:role:create', ['role' => 'viewer', 'policies' => ['allow GET /.*/']]);

    $this->artisan('jwta:role:update', ['role' => 'viewer', 'policies' => ['deny POST /.*/']])
        ->expectsOutput('Role [viewer] updated.')
        ->assertSuccessful();

    expect($this->manager->get('viewer')[0]->action)->toBe('deny');
});

it('does not update a missing role', function () {
    $this->artisan('jwta:role:update', ['role' => 'ghost', 'policies' => ['allow GET /.*/']])
        ->expectsOutput('Role [ghost] not found.')
        ->assertFailed();
});

it('deletes a role after confirmation', function () {
    $this->artisan('jwta:role:create', ['role' => 'viewer', 'policies' => ['allow GET /.*/']]);

    $this->artisan('jwta:role:delete', ['role' => 'viewer'])
        ->expectsConfirmation('Delete role [viewer]?', 'yes')
        ->expectsOutput('Role [viewer] deleted.')
        ->assertSuccessful();

    expect($this->manager->exists('viewer'))->toBeFalse();
});

it('keeps the role when deletion is not confirmed', function () {
    $this->artisan('jwta:role:create', ['role' => 'viewer', 'policies' => ['allow GET /.*/']]);

    $this->artisan('jwta:role:delete', ['role' => 'viewer'])
        ->expectsConfirmation('Delete role [viewer]?', 'no')
        ->expectsOutput('Cancelled.')
        ->assertSuccessful();

    expect($this->manager->exists('viewer'))->toBeTrue();
});

it('deletes a role without confirmation', function (array $options) {
    $this->artisan('jwta:role:create', ['role' => 'viewer', 'policies' => ['allow GET /.*/']]);

    $this->artisan('jwta:role:delete', ['role' => 'viewer', ...$options])->assertSuccessful();

    expect($this->manager->exists('viewer'))->toBeFalse();
})->with([
    'forced' => [['--force' => true]],
    'non interactive' => [['--no-interaction' => true]],
]);

it('does not delete a missing role', function () {
    $this->artisan('jwta:role:delete', ['role' => 'ghost', '--force' => true])
        ->expectsOutput('Role [ghost] not found.')
        ->assertFailed();
});

it('lists the roles', function () {
    $this->artisan('jwta:role:create', ['role' => 'viewer', 'policies' => ['allow GET /.*/']]);
    $this->artisan('jwta:role:create', ['role' => 'admin', 'policies' => ['allow * /.*/']]);

    $this->artisan('jwta:role:list')
        ->expectsOutput('admin')
        ->expectsOutput('viewer')
        ->assertSuccessful();
});

it('says when there are no roles', function () {
    $this->artisan('jwta:role:list')
        ->expectsOutput('No roles found.')
        ->assertSuccessful();
});

it('shows the policies of a role as json', function () {
    $this->artisan('jwta:role:create', ['role' => 'viewer', 'policies' => ['allow GET /\/users/']]);

    $this->artisan('jwta:role:show', ['role' => 'viewer'])
        ->expectsOutputToContain('"pathex": "/\\\\/users/"')
        ->assertSuccessful();
});

it('does not show a missing role', function () {
    $this->artisan('jwta:role:show', ['role' => 'ghost'])
        ->expectsOutput('Role [ghost] not found.')
        ->assertFailed();
});

it('no longer registers the placeholder command', function () {
    expect(Artisan::all())->not->toHaveKey('jwtauthorize:placeholder');
});

it('tests an allowed request against a role', function () {
    $this->manager->create('editor', app(PolicyBuilder::class)->fromList([
        'deny * /\/admin(\/.*)?/' => ['allow GET /\/admin\/reports/'],
        'allow GET /.*/',
    ]));

    $this->artisan('jwta:role:test', ['role' => 'editor', 'method' => 'get', 'path' => '/admin/reports?x=1'])
        ->expectsOutputToContain('ALLOWED  GET /admin/reports  (role: editor)')
        ->expectsOutputToContain('allow GET /\/admin\/reports/  ← decides')
        ->assertSuccessful();
});

it('tests a denied request against a role', function () {
    $this->manager->create('editor', app(PolicyBuilder::class)->fromList([
        'deny * /\/admin(\/.*)?/' => ['allow GET /\/admin\/reports/'],
        'allow GET /.*/',
    ]));

    $this->artisan('jwta:role:test', ['role' => 'editor', 'method' => 'POST', 'path' => '/admin/users'])
        ->expectsOutputToContain('DENIED  POST /admin/users  (role: editor)')
        ->expectsOutputToContain('deny * /\/admin(\/.*)?/  ← decides')
        ->assertFailed();
});

it('reports when no policy matched', function () {
    $this->manager->create('viewer', collect([new Policy('allow', 'GET', '/.*/')]));

    $this->artisan('jwta:role:test', ['role' => 'viewer', 'method' => 'DELETE', 'path' => '/x'])
        ->expectsOutputToContain('No policy matched.')
        ->assertFailed();
});

it('rejects an unknown role or method when testing', function (string $role, string $method, string $message) {
    $this->manager->create('viewer', collect([new Policy('allow', 'GET', '/.*/')]));

    $this->artisan('jwta:role:test', ['role' => $role, 'method' => $method, 'path' => '/'])
        ->expectsOutputToContain($message)
        ->assertFailed();
})->with([
    'unknown role' => ['ghost', 'GET', 'Role [ghost] not found.'],
    'bad method' => ['viewer', 'PULL', 'Method [PULL] invalid.'],
]);

it('prints policies with angle brackets literally', function () {
    $this->manager->create('named', collect([new Policy('allow', 'GET', '/\/users\/(?<id>\d+)/')]));

    $this->artisan('jwta:role:test', ['role' => 'named', 'method' => 'GET', 'path' => '/users/7'])
        ->expectsOutputToContain('allow GET /\/users\/(?<id>\d+)/')
        ->assertSuccessful();
});
