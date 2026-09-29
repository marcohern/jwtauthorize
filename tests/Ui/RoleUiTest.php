<?php

declare(strict_types=1);

use Illuminate\Support\Facades\Gate;
use Illuminate\Support\Facades\Storage;
use Marcohern\Jwtauthorize\PolicyBuilder;
use Marcohern\Jwtauthorize\PolicyManager;

beforeEach(function () {
    Storage::fake('local');
    $this->manager = app(PolicyManager::class);
    $this->manager->create('editor', app(PolicyBuilder::class)->fromList([
        'allow GET /.*/',
        'deny * /\/admin(\/.*)?/' => ['allow GET /\/admin\/reports/'],
    ]));
});

it('lists roles with their policy count', function () {
    $this->get('/jwta/roles')
        ->assertOk()
        ->assertSee('editor')
        ->assertSee(route('jwtauthorize.roles.show', 'editor'), false);
});

it('shows the nested policies of a role', function () {
    $this->get('/jwta/roles/editor')
        ->assertOk()
        ->assertSeeInOrder(['/.*/', '/\/admin(\/.*)?/', '/\/admin\/reports/'])
        ->assertSee('badge-deny', false);
});

it('responds 404 for an unknown role', function (string $method, string $uri) {
    $this->call($method, $uri, ['direction' => 'up'])->assertNotFound();
})->with([
    'show' => ['GET', '/jwta/roles/ghost'],
    'edit' => ['GET', '/jwta/roles/ghost/edit'],
    'update' => ['PUT', '/jwta/roles/ghost'],
    'move' => ['PATCH', '/jwta/roles/ghost/policies/0/move'],
    'delete' => ['DELETE', '/jwta/roles/ghost'],
]);

it('renders the create form with one empty row', function () {
    $this->get('/jwta/roles/create')
        ->assertOk()
        ->assertSee('name="name"', false)
        ->assertSee('name="policies[0][pathex]"', false);
});

it('creates a nested role from the form rows', function () {
    $this->post('/jwta/roles', [
        'name' => 'support',
        'policies' => [
            ['action' => 'deny', 'methods' => '*', 'pathex' => '/\/orgs(\/.*)?/', 'depth' => 0],
            ['action' => 'allow', 'methods' => 'get, post', 'pathex' => '/\/orgs\/tickets(\/.*)?/', 'depth' => 1],
            ['action' => 'allow', 'methods' => 'GET', 'pathex' => '/.*/', 'depth' => 0],
        ],
    ])->assertRedirect('/jwta/roles/support')->assertSessionHas('status', 'Role [support] created.');

    expect($this->manager->claim('support'))->toBe([
        ['action' => 'deny', 'methods' => '*', 'pathex' => '/\/orgs(\/.*)?/', 'children' => [
            ['action' => 'allow', 'methods' => 'GET,POST', 'pathex' => '/\/orgs\/tickets(\/.*)?/', 'children' => []],
        ]],
        ['action' => 'allow', 'methods' => 'GET', 'pathex' => '/.*/', 'children' => []],
    ]);
});

it('rejects invalid role forms', function (array $input, string $errorKey) {
    $this->from('/jwta/roles/create')
        ->post('/jwta/roles', $input)
        ->assertRedirect('/jwta/roles/create')
        ->assertSessionHasErrors($errorKey);

    expect($this->manager->all()->all())->toBe(['editor']);
})->with([
    'existing name' => [['name' => 'editor', 'policies' => [['action' => 'allow', 'methods' => '*', 'pathex' => '/.*/', 'depth' => 0]]], 'name'],
    'invalid name' => [['name' => '../x', 'policies' => [['action' => 'allow', 'methods' => '*', 'pathex' => '/.*/', 'depth' => 0]]], 'name'],
    'reserved name' => [['name' => 'create', 'policies' => [['action' => 'allow', 'methods' => '*', 'pathex' => '/.*/', 'depth' => 0]]], 'name'],
    'no policies' => [['name' => 'x', 'policies' => []], 'policies'],
    'bad action' => [['name' => 'x', 'policies' => [['action' => 'accept', 'methods' => '*', 'pathex' => '/.*/', 'depth' => 0]]], 'policies.0.action'],
    'bad methods' => [['name' => 'x', 'policies' => [['action' => 'allow', 'methods' => 'PUST', 'pathex' => '/.*/', 'depth' => 0]]], 'policies.0'],
    'bad regex on row 2' => [['name' => 'x', 'policies' => [
        ['action' => 'allow', 'methods' => '*', 'pathex' => '/.*/', 'depth' => 0],
        ['action' => 'deny', 'methods' => '*', 'pathex' => '/(/', 'depth' => 1],
    ]], 'policies.1'],
    'whitespace in regex' => [['name' => 'x', 'policies' => [['action' => 'allow', 'methods' => '*', 'pathex' => '/a b/', 'depth' => 0]]], 'policies.0'],
    'forbidden modifier' => [['name' => 'x', 'policies' => [['action' => 'allow', 'methods' => '*', 'pathex' => '/.*/m', 'depth' => 0]]], 'policies.0'],
    'first row nested' => [['name' => 'x', 'policies' => [['action' => 'allow', 'methods' => '*', 'pathex' => '/.*/', 'depth' => 1]]], 'policies.0'],
    'skipped level' => [['name' => 'x', 'policies' => [
        ['action' => 'allow', 'methods' => '*', 'pathex' => '/.*/', 'depth' => 0],
        ['action' => 'deny', 'methods' => '*', 'pathex' => '/\/a/', 'depth' => 2],
    ]], 'policies.1'],
]);

it('shows row errors next to the submitted rows', function () {
    $this->followingRedirects()
        ->from('/jwta/roles/create')
        ->post('/jwta/roles', ['name' => 'x', 'policies' => [['action' => 'allow', 'methods' => '*', 'pathex' => '/(/', 'depth' => 0]]])
        ->assertOk()
        ->assertSee('value="/(/"', false)
        ->assertSee('field-error', false);
});

it('fills the edit form with the role as rows', function () {
    $this->get('/jwta/roles/editor/edit')
        ->assertOk()
        ->assertSee('value="editor" readonly', false)
        ->assertSee('name="policies[2][pathex]" value="/\/admin\/reports/"', false)
        ->assertSee('name="policies[2][depth]" value="1"', false);
});

it('offers sorting by specificity per level in the role form', function () {
    $this->get('/jwta/roles/editor/edit')
        ->assertOk()
        ->assertSee('data-op="sort-root"', false)
        ->assertSee('data-op="sort"', false);
});

it('replaces the policies of a role', function () {
    $this->put('/jwta/roles/editor', [
        'policies' => [['action' => 'deny', 'methods' => 'POST', 'pathex' => '/.*/', 'depth' => 0]],
    ])->assertRedirect('/jwta/roles/editor')->assertSessionHas('status', 'Role [editor] updated.');

    expect($this->manager->claim('editor'))->toBe([
        ['action' => 'deny', 'methods' => 'POST', 'pathex' => '/.*/', 'children' => []],
    ]);
});

it('moves a top-level policy', function (int $index, string $direction, array $order) {
    $this->patch("/jwta/roles/editor/policies/$index/move", ['direction' => $direction])
        ->assertRedirect('/jwta/roles/editor')
        ->assertSessionHas('status', 'Policy moved.');

    expect(array_column($this->manager->claim('editor'), 'pathex'))->toBe($order);
})->with([
    'down' => [0, 'down', ['/\/admin(\/.*)?/', '/.*/']],
    'up' => [1, 'up', ['/\/admin(\/.*)?/', '/.*/']],
]);

it('keeps children with a moved policy', function () {
    $this->patch('/jwta/roles/editor/policies/1/move', ['direction' => 'up']);

    expect($this->manager->get('editor')[0]->children)->toHaveCount(1);
});

it('does not move a policy past either end', function (int $index, string $direction) {
    $this->patch("/jwta/roles/editor/policies/$index/move", ['direction' => $direction])
        ->assertRedirect('/jwta/roles/editor')
        ->assertSessionHasErrors('move');

    expect(array_column($this->manager->claim('editor'), 'pathex'))->toBe(['/.*/', '/\/admin(\/.*)?/']);
})->with([
    'first up' => [0, 'up'],
    'last down' => [1, 'down'],
    'out of range' => [5, 'down'],
]);

it('rejects an unknown move direction', function () {
    $this->patch('/jwta/roles/editor/policies/0/move', ['direction' => 'left'])
        ->assertSessionHasErrors('direction');
});

it('deletes a role', function () {
    $this->delete('/jwta/roles/editor')
        ->assertRedirect('/jwta/roles')
        ->assertSessionHas('status', 'Role [editor] deleted.');

    expect($this->manager->exists('editor'))->toBeFalse();
});

it('responds 403 when the gate denies', function () {
    Gate::define('jwtauthorize.manage', fn ($user = null) => false);

    $this->get('/jwta/roles')->assertForbidden();
    $this->delete('/jwta/roles/editor')->assertForbidden();
    expect($this->manager->exists('editor'))->toBeTrue();
});
