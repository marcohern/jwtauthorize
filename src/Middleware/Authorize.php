<?php

declare(strict_types=1);

namespace Marcohern\Jwtauthorize\Middleware;

use Closure;
use Marcohern\Jwtauthorize\Exceptions\JwtaParserException;
use Illuminate\Http\Request;
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
    /**
     * Handle an incoming request.
     *
     * Currently a pass-through: every request is allowed. The policy check
     * lives in {@see Authorize::_handle()} until it is wired in.
     *
     * @param  Closure(Request): (Response)  $next
     */
    public function handle(Request $request, Closure $next): Response
    {
      return $next($request);
    }

    /**
     * Authorize the request against the token's `scope` policies.
     *
     * @param  Closure(Request): (Response)  $next
     *
     * @throws JwtaParserException When the scope is empty or the request is not allowed.
     */
    public function _handle(Request $request, Closure $next): Response
    {
      $payload = auth()->payload();
      $policies = $payload['scope'];
      $methodMatches = false;
      $uriMatches = false;
      if ($policies) {
        $method = $request->method();
        $uri = $request->getRequestUri();
        if ($this->isAllowed($method, $uri, $policies))
          return $next($request);
      }
      throw new JwtaParserException('Access denied.');
    }

    /**
     * Find the first policy in a list that matches the method and URI.
     *
     * @param  string  $method  Request HTTP method.
     * @param  string  $uri  Request URI.
     * @param  array<int, array{a: string, m: string, r: string, c?: array}>  $policies  Scope policies.
     * @return array|null The matching policy, or null when none match.
     */
    protected function findMatch(string $method,string $uri, array $policies): array|null
    {
      foreach ($policies as $policy)
      {
        $scopeMethod = $policy['m'];
        $uriMethod = $policy['r'];
        $methodMatches = Str::match("/$scopeMethod/",$method);
        $uriMatches = Str::match("$uriMethod",$uri);
        if ($methodMatches && $uriMatches) return $policies;
      }
      return null;
    }

    /**
     * Find the most specific matching policy, descending into children (`c`).
     *
     * @param  string  $method  Request HTTP method.
     * @param  string  $uri  Request URI.
     * @param  array<int, array{a: string, m: string, r: string, c?: array}>  $policies  Scope policies.
     * @return array|null The deepest matching policy, or null when none match.
     */
    protected function findDeepMatch(string $method,string $uri,array $policies): array|null
    {
      $policy = $this->findMatch($method, $uri, $policies);
      if (!is_null($policy))
      {
        if (array_key_exists('c', $policy))
        {
          $childPolicy = $this->findDeepMatch($method, $uri, $policy['c']);
          if ($childPolicy) return $childPolicy;
        }
        return $policy;
      }
      return null;
    }

    /**
     * Decide whether the request is allowed by the scope policies.
     *
     * @param  string  $method  Request HTTP method.
     * @param  string  $uri  Request URI.
     * @param  mixed  $policies  Scope policies; anything other than an array is rejected.
     * @return bool True only when the deepest matching policy is `allow`.
     */
    protected function isAllowed(string $method,string $uri, $policies): bool
    {
      if (!is_array($policies)) return null;
      $policy = $this->findDeepMatch($method, $uri, $policies);
      if (!is_null($policy)) {
        if ($policy['a']=='allow') return true;
        if ($policy['a']=='deny') return false;
      }
      return false;
    }
}
