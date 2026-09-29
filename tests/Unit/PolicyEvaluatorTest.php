<?php

declare(strict_types=1);

use Marcohern\Jwtauthorize\Evaluation\EvaluationNode;
use Marcohern\Jwtauthorize\Exceptions\JwtaParserException;
use Marcohern\Jwtauthorize\Parser;
use Marcohern\Jwtauthorize\PolicyBuilder;
use Marcohern\Jwtauthorize\PolicyEvaluator;

beforeEach(function () {
    $parser = new Parser;
    $this->builder = new PolicyBuilder($parser);
    $this->evaluator = new PolicyEvaluator($parser);
    $this->evaluate = fn (array $scope, string $method, string $path) => $this->evaluator->evaluate($this->builder->fromList($scope), $method, $path);
});

it('decides like the middleware', function (array $scope, string $method, string $path, bool $allowed) {
    expect(($this->evaluate)($scope, $method, $path)->allowed())->toBe($allowed);
})->with([
    'allow everything' => [['allow * /.*/'], 'GET', '/anything', true],
    'method in a list' => [['allow GET,POST /\/users/'], 'POST', '/users', true],
    'head covered by get' => [['allow GET /\/users/'], 'HEAD', '/users', true],
    'parent allows, no child' => [['allow * /.*/' => ['deny * /\/admin(\/.*)?/']], 'GET', '/users', true],
    'child allows, parent denies' => [['deny * /.*/' => ['allow GET /\/public(\/.*)?/']], 'GET', '/public/page', true],
    'child denies' => [['allow * /.*/' => ['deny * /\/admin(\/.*)?/']], 'GET', '/admin/users', false],
    'top level deny' => [['deny * /.*/'], 'GET', '/users', false],
    'no policy matches' => [['allow GET /\/users/'], 'GET', '/orders', false],
    'method does not match' => [['allow GET /.*/'], 'POST', '/users', false],
    'whole path only' => [['allow GET /\/users/'], 'GET', '/users/1', false],
    'deny after an allow sibling' => [['allow * /.*/', 'deny * /\/admin(\/.*)?/'], 'GET', '/admin/users', false],
]);

it('records the chain from the top-level policy to the deciding one', function () {
    $evaluation = ($this->evaluate)(['allow * /.*/' => ['deny * /\/admin(\/.*)?/' => ['allow GET /\/admin\/reports/']]], 'GET', '/admin/reports');

    expect($evaluation->allowed())->toBeTrue();
    expect(array_map(fn (EvaluationNode $node) => $node->policy->pathex, $evaluation->chain))
        ->toBe(['/.*/', '/\/admin(\/.*)?/', '/\/admin\/reports/']);
    expect($evaluation->decidingNode()?->decides)->toBeTrue();
    expect($evaluation->nodes[0]->onDecisionPath)->toBeTrue();
    expect($evaluation->nodes[0]->decides)->toBeFalse();
});

it('keeps the first matching allow when siblings all allow', function () {
    $evaluation = ($this->evaluate)(['allow GET /.*/', 'allow * /\/users/'], 'GET', '/users');

    expect($evaluation->decidingNode()?->policy->pathex)->toBe('/.*/');
    expect($evaluation->nodes[1]->status)->toBe(EvaluationNode::MATCHED);
    expect($evaluation->nodes[1]->onDecisionPath)->toBeFalse();
});

it('does not reach the siblings after a deciding deny', function () {
    $evaluation = ($this->evaluate)(['deny * /.*/', 'allow * /.*/'], 'GET', '/users');

    expect($evaluation->nodes[0]->decides)->toBeTrue();
    expect($evaluation->nodes[1]->status)->toBe(EvaluationNode::NOT_EVALUATED);
    expect($evaluation->nodes[1]->methodMatched)->toBeNull();
});

it('does not check the children of an unmatched policy', function () {
    $evaluation = ($this->evaluate)(['deny * /\/admin(\/.*)?/' => ['allow GET /\/admin\/reports/'], 'allow GET /.*/'], 'GET', '/users');

    expect($evaluation->nodes[0]->status)->toBe(EvaluationNode::UNMATCHED);
    expect($evaluation->nodes[0]->pathMatched)->toBeFalse();
    expect($evaluation->nodes[0]->children[0]->status)->toBe(EvaluationNode::NOT_EVALUATED);
    expect($evaluation->decidingNode()?->policy->pathex)->toBe('/.*/');
});

it('does not check the path when the method does not match', function () {
    $evaluation = ($this->evaluate)(['allow POST /.*/'], 'GET', '/users');

    expect($evaluation->nodes[0]->methodMatched)->toBeFalse();
    expect($evaluation->nodes[0]->pathMatched)->toBeNull();
    expect($evaluation->decidingNode())->toBeNull();
    expect($evaluation->allowed())->toBeFalse();
});

it('throws when a policy fails to evaluate', function () {
    $jit = ini_get('pcre.jit');
    $limit = ini_get('pcre.backtrack_limit');
    ini_set('pcre.jit', '0');
    ini_set('pcre.backtrack_limit', '100');

    try {
        ($this->evaluate)(['allow * /.*/' => ['deny * /\/(a+)+[bc]/']], 'GET', '/'.str_repeat('a', 30));
    } finally {
        ini_set('pcre.jit', $jit);
        ini_set('pcre.backtrack_limit', $limit);
    }
})->throws(JwtaParserException::class, 'Path match failed.');

it('normalizes paths like the middleware', function (string $input, string $path) {
    expect(PolicyEvaluator::normalizePath($input))->toBe($path);
})->with([
    'plain' => ['/admin/users', '/admin/users'],
    'no leading slash' => ['admin/users', '/admin/users'],
    'trailing slash' => ['/admin/users/', '/admin/users'],
    'query and fragment' => ['/admin/users?page=2#top', '/admin/users'],
    'encoded' => ['/%61dmin/users', '/admin/users'],
    'full url' => ['https://example.com/api/users?x=1', '/api/users'],
    'double leading slash' => ['//admin', '/admin'],
    'root' => ['/', '/'],
    'empty' => ['', '/'],
    'encoded trailing slash kept' => ['/users%2F', '/users/'],
]);
