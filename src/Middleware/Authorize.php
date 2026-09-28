<?php

declare(strict_types=1);

namespace Marcohern\Jwtauthorize\Middleware;

use Closure;
use Marcohern\Jwtauthorize\Exceptions\JwtaParserException;
use Marcohern\Jwtauthorize\Parser;
use Marcohern\Jwtauthorize\Policy;
use Marcohern\Jwtauthorize\PolicyBuilder;
use Illuminate\Http\Request;
use Illuminate\Support\Collection;
use Illuminate\Support\Str;
use Symfony\Component\HttpFoundation\Response;


/**
 * Middleware that authorizes requests against the policies in the JWT `scope` claim.
 *
 * The scope is a list of policies, each with the keys:
 *  - `a`: action, `allow` or `deny`
 *  - `m`: HTTP method pattern
 *  - `r`: URI regular expression
 *  - `c`: optional list of child policies, using the same keys
 *
 * The deepest matching policy decides the outcome.
 */
class Authorize
{
  public function __construct(
    private readonly PolicyBuilder $builder,
    private readonly Parser $parser)
  {

  }
    /**
     *Authorize the request against the token's `scope` policies.
     *
     * @param  Closure(Request): (Response)  $next
     *
     * @throws JwtaParserException When the scope is empty or the request is not allowed.
     */
    public function handle(Request $request, Closure $next): Response
    {
      $payload = auth()->payload();
      $scope = $payload->get('scope');
      if (empty($scope)) throw new JwtaParserException('Access denied.');

      $policies = $this->builder->fromList($scope);
      $method = $request->method();
      $uri = $request->getRequestUri();
      $policy = $this->findDeepMatch($method, $uri, $policies);
      if (is_null($policy)) throw new JwtaParserException('Access denied.');

      if ($policy->action === 'allow') return $next($request);
      throw new JwtaParserException('Access denied.');
    }

    /**
     * Find the first policy in a list that matches the method and URI.
     *
     * @param  string  $method  Request HTTP method.
     * @param  string  $uri  Request URI.
     * @param  Collection $policies  Scope policies.
     * @return Policy|null The matching policy, or null when none match.
     */
    protected function findMatch(string $method,string $uri, Collection $policies): Policy|null
    {
      foreach ($policies as $policy)
      {
        $scopeMethod = $policy->methods;
        $uriMethod = $policy->pathex;
        if ($this->parser->isMatch($policy, $method, $uri)) return $policy;
      }
      return null;
    }

    /**
     * Find the most specific matching policy, descending into children (`c`).
     *
     * @param  string  $method  Request HTTP method.
     * @param  string  $uri  Request URI.
     * @param  Collection $policies  Scope policies.
     * @return Policy|null The deepest matching policy, or null when none match.
     */
    protected function findDeepMatch(string $method,string $uri,Collection $policies): Policy|null
    {
      $policy = $this->findMatch($method, $uri, $policies);
      if (!is_null($policy))
      {
        if ($policy->children->count() > 0)
        {
          return $this->findDeepMatch($method, $uri, $policy->children);
        }
        return $policy;
      }
      return null;
    }
}
