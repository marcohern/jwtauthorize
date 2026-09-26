<?php

declare(strict_types=1);

namespace Marcohern\Jwtauthorize\Middleware;

use Closure;
use Illuminate\Auth\Access\AuthorizationException;
use Illuminate\Http\Request;
use Illuminate\Support\Str;
use Symfony\Component\HttpFoundation\Response;

class Authorize
{
    /**
     * Handle an incoming request.
     *
     * @param  Closure(Request): (Response)  $next
     */
    public function _handle(Request $request, Closure $next): Response
    {
      return $next($request);
    }

    public function handle(Request $request, Closure $next): Response
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
      throw new AuthorizationException('Access denied.');
    }

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
