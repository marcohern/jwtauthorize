<?php

declare(strict_types=1);

namespace Marcohern\Jwtauthorize\Middleware;

use Closure;
use Illuminate\Http\Request;
use Illuminate\Support\Collection;
use LogicException;
use Marcohern\Jwtauthorize\Exceptions\JwtaForbiddenException;
use Marcohern\Jwtauthorize\Exceptions\JwtaParserException;
use Marcohern\Jwtauthorize\Exceptions\JwtaUnauthorizedException;
use Marcohern\Jwtauthorize\Jwtauthorize;
use Marcohern\Jwtauthorize\Parser;
use Marcohern\Jwtauthorize\Policy;
use Marcohern\Jwtauthorize\PolicyBuilder;
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
 *  - Among matching siblings, `deny` wins over `allow`.
 *  - Anything else fails closed: no match, an empty or malformed claim, or a
 *    policy that fails to evaluate is a 403; a missing or invalid token is a 401.
 */
class Authorize
{
    /**
     * @param  PolicyBuilder  $builder  Builder used to load the claim's policies.
     * @param  Parser  $parser  Parser used to match policies against the request.
     */
    public function __construct(
        private readonly PolicyBuilder $builder,
        private readonly Parser $parser) {}

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
            $policy = $this->findDeepMatch($request->method(), $path, $this->builder->fromList($scope));
        } catch (Throwable $e) {
            throw new JwtaForbiddenException('Access denied.', $e);
        }

        if ($policy?->action !== 'allow') {
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

    /**
     * Find the policy that decides the request.
     *
     * Every matching sibling is evaluated, descending into its children; a
     * `deny` from any of them wins, otherwise the first `allow` decides.
     *
     * @param  string  $method  Request HTTP method.
     * @param  string  $path  Decoded request path.
     * @param  Collection<int, Policy>  $policies  Policies to evaluate.
     * @return Policy|null The deciding policy, or null when none match.
     *
     * @throws JwtaParserException When a policy fails to evaluate.
     */
    protected function findDeepMatch(string $method, string $path, Collection $policies): ?Policy
    {
        $decision = null;
        foreach ($policies as $policy) {
            if (! $this->parser->isMatch($policy, $method, $path)) {
                continue;
            }

            $effective = $this->findDeepMatch($method, $path, $policy->children) ?? $policy;

            if ($effective->action === 'deny') {
                return $effective;
            }
            $decision ??= $effective;
        }

        return $decision;
    }
}
