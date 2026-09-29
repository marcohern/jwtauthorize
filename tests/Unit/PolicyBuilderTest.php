<?php

declare(strict_types=1);

use Illuminate\Support\Collection;
use Marcohern\Jwtauthorize\Exceptions\JwtaParserException;
use Marcohern\Jwtauthorize\Parser;
use Marcohern\Jwtauthorize\Policy;
use Marcohern\Jwtauthorize\PolicyBuilder;

beforeEach(function () {
    $this->parser = new Parser;
    $this->builder = new PolicyBuilder($this->parser);
});

// Runs AFTER every test in this file
afterEach(function () {});

test('[PolicyBuilder::from] can build an instance of Policy from string', function (string $source, string $action, string $methods, string $pathex) {
    $policy = $this->builder->from($source);

    expect($policy->action)->toBe($action);
    expect($policy->methods)->toBe($methods);
    expect($policy->pathex)->toBe($pathex);
})->with([
    ['allow * /.*/', 'allow', '*', '/.*/'],
    ['deny POST /\/admin(\/.*)?/', 'deny', 'POST', '/\/admin(\/.*)?/'],
    ['allow DELETE /\/somethig\/\d+/', 'allow', 'DELETE', '/\/somethig\/\d+/'],
]);

test('[PolicyBuilder::from] can build an instance of Policy from stdclass', function (array $source, string $action, string $methods, string $pathex) {
    $object = (object) $source;

    $policy = $this->builder->from($object);

    expect($policy->action)->toBe($action);
    expect($policy->methods)->toBe($methods);
    expect($policy->pathex)->toBe($pathex);
})->with([
    [['action' => 'allow', 'methods' => '*', 'pathex' => '/.*/'], 'allow', '*', '/.*/'],
    [['action' => 'deny', 'methods' => 'POST', 'pathex' => '/\/admin/'], 'deny', 'POST', '/\/admin/'],
]);
test('[PolicyBuilder::from] can build an instance of Policy from Policy', function (Policy $source, string $action, string $methods, string $pathex) {
    $policy = $this->builder->from($source);

    expect($policy->action)->toBe($action);
    expect($policy->methods)->toBe($methods);
    expect($policy->pathex)->toBe($pathex);
})->with([
    [new Policy('allow', '*', '/.*/'), 'allow', '*', '/.*/'],
]);

test('[PolicyBuilder::from] can build an instance of Policy recursively', function (string $key, array $children, int $childCount) {
    $policy = $this->builder->from($key, $children);

    expect(count($policy->children))->toBe($childCount);
})->with([
    ['allow * /.*/', [
        'deny * /\/admin(\/.*)?/',
        'deny * /\/users(\/.*)?/',
        'deny * /\/orgs(\/.*)?/' => ['allow * /\/orgs\/reports1(\/.*)?/', 'allow * /\/orgs\/reports2(\/.*)?/'],
    ], 3],
]);

test('[PolicyBuilder::fromList] can parse a list of valid Policies', function (array $source, int $count) {
    $policies = $this->builder->fromList($source);

    expect($policies instanceof Collection)->toBeTrue();
    expect($policies[0] instanceof Policy)->toBeTrue();
    expect(count($policies))->toBe($count);
})->with([
    [['allow * /.*/', 'deny POST /.*/', 'deny * /\/admin(\/.*)?/'], 3],
]);

test('[PolicyBuilder::from] can build an instance of Policy from an associative array with children', function () {
    $policy = $this->builder->from([
        'action' => 'deny', 'methods' => '*', 'pathex' => '/\/admin(\/.*)?/',
        'children' => [['action' => 'allow', 'methods' => 'GET', 'pathex' => '/\/admin\/reports/', 'children' => []]],
    ]);

    expect($policy->action)->toBe('deny');
    expect($policy->children)->toHaveCount(1);
    expect($policy->children[0]->pathex)->toBe('/\/admin\/reports/');
});

test('[PolicyBuilder::fromList] round-trips the array shape of Policy::toArray()', function () {
    $policies = $this->builder->fromList(['allow GET /.*/', 'deny * /\/admin(\/.*)?/' => ['allow GET /\/admin\/reports/']]);

    $claim = $policies->map(fn (Policy $policy) => $policy->toArray())->all();

    expect(json_encode($this->builder->fromList($claim)))->toBe(json_encode($policies));
});

test('[PolicyBuilder::from] appends extra children to a Policy', function () {
    $policy = $this->builder->from(new Policy('allow', '*', '/.*/'), ['deny * /\/admin/']);

    expect($policy->children)->toHaveCount(1);
    expect($policy->children[0]->action)->toBe('deny');
});

test('[PolicyBuilder::from] validates array and stdClass definitions', function (mixed $source, string $message) {
    expect(fn () => $this->builder->from($source))->toThrow(JwtaParserException::class, $message);
})->with([
    'bad action' => [['action' => 'Allow', 'methods' => '*', 'pathex' => '/.*/'], 'Policy invalid.'],
    'missing pathex' => [['action' => 'allow', 'methods' => '*'], 'Policy invalid.'],
    'non string key' => [['action' => 'allow', 'methods' => ['GET'], 'pathex' => '/.*/'], 'Policy invalid.'],
    'bad children' => [['action' => 'allow', 'methods' => '*', 'pathex' => '/.*/', 'children' => 'x'], 'Policy invalid.'],
    'bad child' => [['action' => 'allow', 'methods' => '*', 'pathex' => '/.*/', 'children' => ['allow PUST /.*/']], 'Policy invalid.'],
    'broken regex' => [(object) ['action' => 'allow', 'methods' => '*', 'pathex' => '/(/'], 'Path in policy invalid.'],
]);

test('[PolicyBuilder::from] rejects unsupported definitions', function (mixed $source) {
    $this->builder->from($source);
})->throws(JwtaParserException::class, 'Unable to build a policy from')->with([
    'integer' => [42],
    'list' => [[['allow * /.*/']]],
    'null' => [null],
]);

test('[PolicyBuilder::fromList] requires a list of children under a string key', function () {
    $this->builder->fromList(['allow * /.*/' => 'deny * /\/admin/']);
})->throws(JwtaParserException::class, 'Children of [allow * /.*/] must be a list.');
