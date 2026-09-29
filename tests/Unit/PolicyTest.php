<?php

declare(strict_types=1);

use Marcohern\Jwtauthorize\Policy;

test('[Policy::__construct] can build an instance of Policy', function (string $action, string $methods, string $pathex) {
    $policy = new Policy($action, $methods, $pathex, collect([]));

    expect($policy->action)->toBe($action);
    expect($policy->methods)->toBe($methods);
    expect($policy->pathex)->toBe($pathex);
})->with([
    ['allow', '*', '/.*/'],
    ['deny', 'GET', '/\/admin(\/.*)?/'],
]);
