<?php

declare(strict_types=1);

use Illuminate\Support\Collection;
use Illuminate\Support\Facades\Storage;
use Marcohern\Jwtauthorize\Exceptions\JwtaRoleException;
use Marcohern\Jwtauthorize\Policy;
use Marcohern\Jwtauthorize\PolicyBuilder;
use Marcohern\Jwtauthorize\PolicyManager;

beforeEach(function () {
    Storage::fake('local');
    $this->manager = app(PolicyManager::class);
    $this->allowAll = collect([new Policy('allow', '*', '/.*/')]);
});

it('creates a role file in private storage', function () {
    $this->manager->create('admin', $this->allowAll);

    Storage::disk('local')->assertExists('jwta/roles/admin.json');
    expect(json_decode(Storage::disk('local')->get('jwta/roles/admin.json'), true))->toBe([
        ['action' => 'allow', 'methods' => '*', 'pathex' => '/.*/', 'children' => []],
    ]);
    expect($this->manager->exists('admin'))->toBeTrue();
});

it('does not create a role that already exists', function () {
    $this->manager->create('admin', $this->allowAll);
    $this->manager->create('admin', $this->allowAll);
})->throws(JwtaRoleException::class, 'Role [admin] already exists.');

it('replaces the policies of an existing role', function () {
    $this->manager->create('admin', $this->allowAll);

    $this->manager->update('admin', collect([new Policy('deny', 'POST', '/.*/')]));

    $policies = $this->manager->get('admin');
    expect($policies)->toHaveCount(1);
    expect($policies[0]->action)->toBe('deny');
    expect($policies[0]->methods)->toBe('POST');
});

it('does not update a missing role', function () {
    $this->manager->update('ghost', $this->allowAll);
})->throws(JwtaRoleException::class, 'Role [ghost] not found.');

it('deletes an existing role', function () {
    $this->manager->create('admin', $this->allowAll);

    $this->manager->delete('admin');

    Storage::disk('local')->assertMissing('jwta/roles/admin.json');
    expect($this->manager->exists('admin'))->toBeFalse();
});

it('does not delete a missing role', function () {
    $this->manager->delete('ghost');
})->throws(JwtaRoleException::class, 'Role [ghost] not found.');

it('loads back the same nested policies it stored', function () {
    $stored = app(PolicyBuilder::class)->fromList([
        'allow GET /.*/',
        'deny * /\/admin(\/.*)?/' => ['allow GET /\/admin\/reports/'],
    ]);
    $this->manager->create('editor', $stored);

    $loaded = $this->manager->get('editor');

    expect($loaded)->toBeInstanceOf(Collection::class)->toHaveCount(2);
    expect($loaded->every(fn ($policy) => $policy instanceof Policy))->toBeTrue();
    expect(json_encode($loaded))->toBe(json_encode($stored));
    expect($loaded[1]->children)->toHaveCount(1);
    expect($loaded[1]->children[0]->pathex)->toBe('/\/admin\/reports/');
});

it('stores filtered collections as a list', function () {
    $policies = collect([new Policy('deny', '*', '/x/'), new Policy('allow', '*', '/.*/')])
        ->filter(fn (Policy $policy) => $policy->action === 'allow');

    $this->manager->create('filtered', $policies);

    expect($this->manager->get('filtered'))->toHaveCount(1);
});

it('does not load a missing role', function () {
    $this->manager->get('ghost');
})->throws(JwtaRoleException::class, 'Role [ghost] not found.');

it('lists all role names', function () {
    $this->manager->create('viewer', $this->allowAll);
    $this->manager->create('admin', $this->allowAll);

    expect($this->manager->all()->all())->toBe(['admin', 'viewer']);
});

it('rejects invalid role names', function (string $role) {
    $this->manager->create($role, $this->allowAll);
})->throws(JwtaRoleException::class)->with([
    'parent traversal' => ['../etc'],
    'sub folder'       => ['a/b'],
    'empty'            => [''],
    'dot'              => ['admin.json'],
]);
