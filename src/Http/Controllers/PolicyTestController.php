<?php

declare(strict_types=1);

namespace Marcohern\Jwtauthorize\Http\Controllers;

use Illuminate\Contracts\View\Factory;
use Illuminate\Contracts\View\View;
use Illuminate\Http\Request;
use Illuminate\Validation\Rule;
use Marcohern\Jwtauthorize\Exceptions\JwtaParserException;
use Marcohern\Jwtauthorize\Parser;
use Marcohern\Jwtauthorize\PolicyEvaluator;
use Marcohern\Jwtauthorize\PolicyManager;

/**
 * Page to test a role: whether it allows a method and path, and which policies decided.
 *
 * It is a GET form, so every result has a shareable URL.
 */
class PolicyTestController
{
    /**
     * @param  PolicyManager  $manager  Role storage.
     * @param  PolicyEvaluator  $evaluator  The decision used by the middleware.
     * @param  Parser  $parser  Provides the HTTP methods.
     * @param  Factory  $views  Renders the package views.
     */
    public function __construct(
        private readonly PolicyManager $manager,
        private readonly PolicyEvaluator $evaluator,
        private readonly Parser $parser,
        private readonly Factory $views,
    ) {}

    /**
     * Show the form and, once a role, method and path are given, the evaluation.
     */
    public function __invoke(Request $request): View
    {
        $roles = $this->manager->all();
        $methods = $this->parser->methods();
        $data = ['roles' => $roles, 'methods' => $methods, 'evaluation' => null, 'failure' => null, 'input' => null];

        if (! $request->filled(['role', 'method', 'path'])) {
            return $this->views->make('jwtauthorize::test', $data);
        }

        $input = $request->validate([
            'role' => ['required', 'string', Rule::in($roles->all())],
            'method' => ['required', 'string', Rule::in($methods)],
            'path' => ['required', 'string', 'max:2000'],
        ], ['role.in' => 'The selected role does not exist.']);
        $data['input'] = $input;

        try {
            $data['evaluation'] = $this->evaluator->evaluate(
                $this->manager->get($input['role']),
                $input['method'],
                PolicyEvaluator::normalizePath($input['path']),
            );
        } catch (JwtaParserException $e) {
            $data['failure'] = $e->getMessage();
        }

        return $this->views->make('jwtauthorize::test', $data);
    }
}
