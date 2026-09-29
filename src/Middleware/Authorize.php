<?php

declare(strict_types=1);

namespace Marcohern\Jwtauthorize\Middleware;

use Closure;
use Illuminate\Http\Request;
use LogicException;
use Marcohern\Jwtauthorize\Exceptions\JwtaForbiddenException;
use Marcohern\Jwtauthorize\Exceptions\JwtaUnauthorizedException;
use Marcohern\Jwtauthorize\Jwtauthorize;
use Marcohern\Jwtauthorize\Parser;
use Marcohern\Jwtauthorize\Policy;
use Marcohern\Jwtauthorize\PolicyBuilder;
use Marcohern\Jwtauthorize\PolicyEvaluator;
use Marcohern\Jwtauthorize\PolicyManager;
use Symfony\Component\HttpFoundation\Response;
use Throwable;

/**
 * Middleware that authorizes requests against the policies in a JWT claim.
 *
 * The claim (`jwtauthorize.claim`, `scope` by default) is a list of policy
 * strings (see {@see Parser}). A string key holds a policy whose value is the
 * list of its children (see {@see PolicyBuilder::fromList()}):
 *
 * ```php
 * ['allow * /.*\/' => ['deny * /\/admin(\/.*)?/']]
 * ```
 *
 * It may also hold the array shape of {@see Policy::toArray()}, which is what
 * {@see PolicyManager::claim()} returns for a role.
 *
 * Register it on routes with the `jwta` alias, or with {@see Jwtauthorize::middleware()}.
 *
 * Rules:
 *  - Policies are matched against the decoded request path (no query string),
 *    the same path Laravel routes on, and must match the whole path.
 *  - A matching policy's children refine it; when none of them match, the
 *    policy itself decides.
 *  - Among matching siblings, `deny` wins over `allow` (see {@see PolicyEvaluator}).
 *  - Anything else fails closed: no match, an empty or malformed claim, or a
 *    policy that fails to evaluate is a 403; a missing or invalid token is a 401.
 */
class Authorize
{
    /**
     * @param  PolicyBuilder  $builder  Builder used to load the claim's policies.
     * @param  PolicyEvaluator  $evaluator  Decides whether the policies allow the request.
     */
    public function __construct(
        private readonly PolicyBuilder $builder,
        private readonly PolicyEvaluator $evaluator) {}

    /**
     * Authorize the request against the token's policies.
     *
     * @param  Closure(Request): (Response)  $next
     *
     * @throws JwtaUnauthorizedException When the request is not authenticated.
     * @throws JwtaForbiddenException When the policies do not allow the request.
     */
    public function handle(Request $request, Closure $next): Response
    {
        $scope = $this->scope();
        $path = '/'.ltrim($request->decodedPath(), '/');

        try {
            $allowed = $this->evaluator->evaluate($this->builder->fromList($scope), $request->method(), $path)->allowed();
        } catch (Throwable $e) {
            throw new JwtaForbiddenException('Access denied.', $e);
        }

        if (! $allowed) {
            throw new JwtaForbiddenException('Access denied.');
        }

        return $next($request);
    }

    /**
     * Read the policies from the authenticated token.
     *
     * @return array<int|string, mixed> Raw policy definitions.
     *
     * @throws JwtaUnauthorizedException When the request is not authenticated.
     * @throws JwtaForbiddenException When the claim is missing, empty or not a list.
     * @throws LogicException When the configured guard is not a JWT guard.
     */
    protected function scope(): array
    {
        $guardName = config('jwtauthorize.guard');
        $guard = auth()->guard($guardName);

        if (! method_exists($guard, 'payload')) {
            throw new LogicException('The ['.($guardName ?? 'default').'] guard is not a JWT guard.');
        }

        if (! $guard->check()) {
            throw new JwtaUnauthorizedException('Unauthenticated.');
        }

        $scope = $guard->payload()->get(config('jwtauthorize.claim', 'scope'));

        if (! is_array($scope) || $scope === []) {
            throw new JwtaForbiddenException('Access denied.');
        }

        return $scope;
    }
}
