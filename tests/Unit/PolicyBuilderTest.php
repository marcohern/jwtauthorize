<?php

declare(strict_types=1);

use Illuminate\Support\Collection;
use Marcohern\Jwtauthorize\Parser;
use Marcohern\Jwtauthorize\Policy;
use Marcohern\Jwtauthorize\PolicyBuilder;

beforeEach(function () {
    $this->parser = new Parser;
    $this->builder = new PolicyBuilder($this->parser);
});

// Runs AFTER every test in this file
afterEach(function ()
{
  
});

test('[Policy::__construct] can build an instance of Policy', function (string $action, string $methods, string $pathex) {
    $policy = new Policy($action, $methods, $pathex, collect([]));

    expect($policy->action)->toBe($action);
    expect($policy->methods)->toBe($methods);
    expect($policy->pathex)->toBe($pathex);
})->with([
  ['allow','*'  ,'/.*/'],
  ['deny' ,'GET','/\/admin(\/.*)?/'],
]);

test('[PolicyBuilder::from] can build an instance of Policy from string', function (string $source, string $action, string $methods, string $pathex) {

    $policy = $this->builder->from($source);

    expect($policy->action)->toBe($action);
    expect($policy->methods)->toBe($methods);
    expect($policy->pathex)->toBe($pathex);
})->with([
  ['allow * /.*/'                  , 'allow', '*'     , '/.*/'],
  ['deny POST /\/admin(\/.*)?/'    , 'deny' , 'POST'  , '/\/admin(\/.*)?/'],
  ['allow DELETE /\/somethig\/\d+/', 'allow', 'DELETE', '/\/somethig\/\d+/'],
]);

test('[PolicyBuilder::from] can build an instance of Policy from stdclass', function (array $source, string $action, string $methods, string $pathex) {
    $object = (object) $source;

    $policy = $this->builder->from($object);

    expect($policy->action)->toBe($action);
    expect($policy->methods)->toBe($methods);
    expect($policy->pathex)->toBe($pathex);
})->with([
  [['action'=>'allow','methods'=>'*'   ,'pathex'=>'/.*/'], 'allow', '*'     , '/.*/'],
  [['action'=>'deny' ,'methods'=>'POST','pathex'=>'/\/admin/'], 'deny','POST', '/\/admin/'],
]);
test('[PolicyBuilder::from] can build an instance of Policy from Policy', function (Policy $source, string $action, string $methods, string $pathex)
{
    $policy = $this->builder->from($source);

    expect($policy->action)->toBe($action);
    expect($policy->methods)->toBe($methods);
    expect($policy->pathex)->toBe($pathex);
})->with([
  [new Policy('allow','*','/.*/'), 'allow', '*'     , '/.*/'],
]);

test('[PolicyBuilder::from] can build an instance of Policy recursively', function (string $key, array $children, int $childCount) {
    $policy = $this->builder->from($key, $children);

    expect(count($policy->children))->toBe($childCount);
})->with([
  ['allow * /.*/',[
      'deny * /\/admin(\/.*)?/',
      'deny * /\/users(\/.*)?/',
      'deny * /\/orgs(\/.*)?/' => ['allow * /\/orgs\/reports1(\/.*)?/','allow * /\/orgs\/reports2(\/.*)?/'],
  ], 3],
]);

test('[PolicyBuilder::fromList] can parse a list of valid Policies', function (array $source, int $count) {
  $policies = $this->builder->fromList($source);

  expect($policies instanceof Collection)->toBeTrue();
  expect($policies[0] instanceof Policy)->toBeTrue();
  expect(count($policies))->toBe($count);
  
})->with([
  [['allow * /.*/', 'deny POST /.*/', 'deny * /\/admin(\/.*)?/'], 3]
]);