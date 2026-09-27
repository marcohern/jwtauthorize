<?php

declare(strict_types=1);


use Marcohern\Jwtauthorize\Policy;

test('[Policy::__construct] can build an instance of Policy', function (string $action, string $methods, string $pathex) {
    $policy = new Policy($action, $methods, $pathex);

    expect($policy->action)->toBe($action);
    expect($policy->methods)->toBe($methods);
    expect($policy->pathex)->toBe($pathex);
})->with([
  ['allow','*'  ,'/.*/'],
  ['deny' ,'GET','/\/admin(\/.*)?/'],
]);

test('[Policy::from] can build an instance of Policy from string', function (string $source, string $action, string $methods, string $pathex) {
    $policy = Policy::from($source);

    expect($policy->action)->toBe($action);
    expect($policy->methods)->toBe($methods);
    expect($policy->pathex)->toBe($pathex);
})->with([
  ['allow * /.*/'                  , 'allow', '*'     , '/.*/'],
  ['deny POST /\/admin(\/.*)?/'    , 'deny' , 'POST'  , '/\/admin(\/.*)?/'],
  ['allow DELETE /\/somethig\/\d+/', 'allow', 'DELETE', '/\/somethig\/\d+/'],
]);

test('[Policy::from] can build an instance of Policy from stdclass', function (array $source, string $action, string $methods, string $pathex) {
    $object = (object) $source;

    $policy = Policy::from($object);

    expect($policy->action)->toBe($action);
    expect($policy->methods)->toBe($methods);
    expect($policy->pathex)->toBe($pathex);
})->with([
  [['action'=>'allow','methods'=>'*'   ,'pathex'=>'/.*/'], 'allow', '*'     , '/.*/'],
  [['action'=>'deny' ,'methods'=>'POST','pathex'=>'/\/admin/'], 'deny','POST', '/\/admin/'],
]);
test('[Policy::from] can build an instance of Policy from Policy', function (Policy $source, string $action, string $methods, string $pathex)
{
    $policy = Policy::from($source);

    expect($policy->action)->toBe($action);
    expect($policy->methods)->toBe($methods);
    expect($policy->pathex)->toBe($pathex);
})->with([
  [new Policy('allow','*','/.*/'), 'allow', '*'     , '/.*/'],
]);

test('[Policy::from] can build an instance of Policy recursively', function (string $key, array $children, int $childCount) {
    $policy = Policy::from($key, $children);

    expect(count($policy->children))->toBe($childCount);
})->with([
  ['allow * /.*/',[
      'deny * /\/admin(\/.*)?/',
      'deny * /\/users(\/.*)?/',
      'deny * /\/orgs(\/.*)?/' => ['allow * /\/orgs\/reports1(\/.*)?/','allow * /\/orgs\/reports2(\/.*)?/'],
  ], 3],
]);

test('[Policy::fromList] can parse a list of valid Policies', function (array $source, int $count) {
  $policies = Policy::fromList($source);

  expect(is_array($policies))->toBeTrue();
  expect($policies[0] instanceof Policy)->toBeTrue();
  expect(count($policies))->toBe($count);
  
})->with([
  [['allow * /.*/', 'deny POST /.*/', 'deny * /\/admin(\/.*)?/'], 3]
]);