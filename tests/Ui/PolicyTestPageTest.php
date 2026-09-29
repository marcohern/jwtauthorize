<?php

declare(strict_types=1);

use Illuminate\Support\Facades\Gate;
use Illuminate\Support\Facades\Storage;
use Marcohern\Jwtauthorize\PolicyBuilder;
use Marcohern\Jwtauthorize\PolicyManager;

beforeEach(function () {
    Storage::fake('local');
    app(PolicyManager::class)->create('editor', app(PolicyBuilder::class)->fromList([
        'deny * /\/admin(\/.*)?/' => ['allow GET /\/admin\/reports/'],
        'allow GET /.*/',
    ]));
});

it('shows the form with the role pre-selected', function () {
    $this->get('/jwta/test?role=editor')
        ->assertOk()
        ->assertSee('<option value="editor" selected>', false)
        ->assertSee('name="path"', false)
        ->assertDontSee('Decided by')
        ->assertDontSee('No policy matched');
});

it('links to the tester from the role page', function () {
    $this->get('/jwta/roles/editor')->assertSee(route('jwtauthorize.test', ['role' => 'editor']), false);
});

it('shows an allowed request with its decision path', function () {
    $this->get('/jwta/test?'.http_build_query(['role' => 'editor', 'method' => 'GET', 'path' => '/admin/reports']))
        ->assertOk()
        ->assertSee('<strong>Allowed</strong>', false)
        ->assertSee('Decided by <code>allow GET /\/admin\/reports/</code>', false)
        ->assertSee('under <code>deny * /\/admin(\/.*)?/</code>', false)
        ->assertSee('<span class="tag">decides</span>', false);
});

it('shows a denied request and the policy that denied it', function () {
    $this->get('/jwta/test?'.http_build_query(['role' => 'editor', 'method' => 'POST', 'path' => 'https://example.com/admin/users?x=1']))
        ->assertOk()
        ->assertSee('<strong>Denied</strong>', false)
        ->assertSee('<code>POST /admin/users</code>', false)
        ->assertSee('normalized from', false)
        ->assertSee('Decided by <code>deny * /\/admin(\/.*)?/</code>', false)
        ->assertSee('not reached', false);
});

it('explains when no policy matched', function () {
    $this->get('/jwta/test?'.http_build_query(['role' => 'editor', 'method' => 'DELETE', 'path' => '/users/1']))
        ->assertOk()
        ->assertSee('<strong>Denied</strong>', false)
        ->assertSee('No policy matched');
});

it('validates the test input', function (array $query, string $field) {
    $this->get('/jwta/test?'.http_build_query($query))->assertSessionHasErrors($field);
})->with([
    'unknown role' => [['role' => 'ghost', 'method' => 'GET', 'path' => '/'], 'role'],
    'bad method' => [['role' => 'editor', 'method' => 'PULL', 'path' => '/'], 'method'],
]);

it('shows that a policy failing to evaluate denies the request', function () {
    Storage::disk('local')->put('jwta/roles/slow.json', json_encode([
        ['action' => 'allow', 'methods' => '*', 'pathex' => '/.*/', 'children' => [
            ['action' => 'deny', 'methods' => '*', 'pathex' => '/\/(a+)+[bc]/', 'children' => []],
        ]],
    ]));
    $jit = ini_get('pcre.jit');
    $limit = ini_get('pcre.backtrack_limit');
    ini_set('pcre.jit', '0');
    ini_set('pcre.backtrack_limit', '100');

    try {
        $response = $this->get('/jwta/test?'.http_build_query(['role' => 'slow', 'method' => 'GET', 'path' => '/'.str_repeat('a', 30)]));
    } finally {
        ini_set('pcre.jit', $jit);
        ini_set('pcre.backtrack_limit', $limit);
    }

    $response->assertOk()->assertSee('<strong>Denied</strong>', false)->assertSee('fails closed');
});

it('requires the manage gate', function () {
    Gate::define('jwtauthorize.manage', fn ($user = null) => false);

    $this->get('/jwta/test?role=editor')->assertForbidden();
});
