<?php

declare(strict_types=1);

use Marcohern\Jwtauthorize\Exceptions\JwtaParserException;
use Marcohern\Jwtauthorize\Http\PolicyRows;
use Marcohern\Jwtauthorize\Parser;
use Marcohern\Jwtauthorize\PolicyBuilder;

beforeEach(function () {
    $this->builder = new PolicyBuilder(new Parser);
    $this->rows = new PolicyRows($this->builder);
});

it('flattens a policy tree into rows, depth first', function () {
    $policies = $this->builder->fromList([
        'allow * /.*/' => [
            'deny * /\/admin(\/.*)?/' => ['allow GET /\/admin\/reports/'],
            'deny POST /\/users/',
        ],
        'deny DELETE /.*/',
    ]);

    expect($this->rows->fromPolicies($policies))->toBe([
        ['action' => 'allow', 'methods' => '*', 'pathex' => '/.*/', 'depth' => 0],
        ['action' => 'deny', 'methods' => '*', 'pathex' => '/\/admin(\/.*)?/', 'depth' => 1],
        ['action' => 'allow', 'methods' => 'GET', 'pathex' => '/\/admin\/reports/', 'depth' => 2],
        ['action' => 'deny', 'methods' => 'POST', 'pathex' => '/\/users/', 'depth' => 1],
        ['action' => 'deny', 'methods' => 'DELETE', 'pathex' => '/.*/', 'depth' => 0],
    ]);
});

it('rebuilds the same tree from its rows', function () {
    $policies = $this->builder->fromList([
        'allow * /.*/' => ['deny * /\/admin(\/.*)?/' => ['allow GET /\/admin\/reports/'], 'deny POST /\/users/'],
        'deny DELETE /.*/',
    ]);

    $rebuilt = $this->rows->toPolicies($this->rows->fromPolicies($policies));

    expect(json_encode($rebuilt))->toBe(json_encode($policies));
});

it('rejects rows that skip a level', function (array $depths) {
    $rows = array_map(fn (int $depth) => ['action' => 'allow', 'methods' => '*', 'pathex' => '/.*/', 'depth' => $depth], $depths);

    $this->rows->toPolicies($rows);
})->throws(JwtaParserException::class)->with([
    'first row nested' => [[1]],
    'jump of two' => [[0, 2]],
]);

it('validates the policies it builds', function () {
    $this->rows->toPolicies([['action' => 'allow', 'methods' => 'PUST', 'pathex' => '/.*/', 'depth' => 0]]);
})->throws(JwtaParserException::class, 'Policy invalid.');
