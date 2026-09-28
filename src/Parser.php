<?php
declare(strict_types=1);

namespace Marcohern\Jwtauthorize;

use Illuminate\Support\Collection;
use Illuminate\Support\Str;
use Marcohern\Jwtauthorize\Exceptions\JwtaParserException;


/**
 * Validates and parses policy strings, and matches requests against policies.
 *
 * A policy string has the form `<action> <methods> <pathex>`:
 *  - action:  `allow` or `deny`
 *  - methods: `*` or a comma separated list of HTTP methods (`GET,POST`)
 *  - pathex:  a delimited regular expression matched against the URI
 *
 * Example: `deny POST /\/admin(\/.*)?/` denies POST to /admin and /admin/...
 */
class Parser {

  /**
   * Alternation of the valid policy actions.
   */
  private const ACTIONS = 'allow|deny';

  /**
   * Alternation of the valid HTTP methods.
   */
  private const METHODS = 'GET|POST|PUT|PATCH|DELETE|HEAD|OPTIONS|CONNECT|TRACE';

  /**
   * Pattern for a comma separated list of HTTP methods (no spaces).
   */
  private const METHOD_LIST = '(('.self::METHODS.'),)*('.self::METHODS.')';

  /**
   * Full policy string pattern.
   *
   * Capture groups: 1 = action, 2 = methods, 6 = pathex.
   */
  private const REGEX = '/^('.self::ACTIONS.') (\*|'.self::METHOD_LIST.') ([^\s]+)$/';

  /**
   * Check whether a policy string follows the policy grammar.
   *
   * Only the grammar is checked; the pathex is not compiled, so a string
   * with an invalid regex may still be reported as valid. Use
   * {@see Parser::extract()} for a full validation.
   *
   * @param  string  $policy  Policy string, e.g. `allow GET /\/users/`.
   * @return bool True when the string matches the grammar.
   */
  public function isValid(string $policy): bool
  {
    return Str::isMatch(self::REGEX, $policy);
  }

  /**
   * Split a policy string into its action, methods and pathex.
   *
   * @param  string  $policy  Policy string.
   * @return array{0: string, 1: string, 2: string} `[action, methods, pathex]`.
   *
   * @throws JwtaParserException `Policy invalid.` when the grammar does not match,
   *                             or `Path in policy invalid.` when the pathex is not a valid regex.
   */
  protected function extractElements(string $policy): array
  {
    $results = null;
    $itMatches = preg_match(self::REGEX, $policy, $groups);
    if ($itMatches === 1)
    {
      $pathex = $groups[6];
      set_error_handler(static fn() => true);
      $isInvalid = (@preg_match($pathex, 'x') === false);
      restore_error_handler();
      if ($isInvalid) throw new JwtaParserException('Path in policy invalid. ['.preg_last_error().'] '.preg_last_error_msg());
      return [$groups[1],$groups[2],$pathex];
      
      return $results;
    }
    throw new JwtaParserException('Policy invalid.');
  }

  /**
   * Parse a policy string into a {@see Policy}.
   *
   * @param  string  $policy  Policy string.
   * @param  Collection<int, Policy>|array<int, Policy>  $children  Already built child policies.
   * @return Policy The parsed policy.
   *
   * @throws JwtaParserException When the string or its pathex is invalid.
   */
  public function extract(string $policy, Collection|array $children = []): Policy
  {
    list($action, $methods, $pathex) = $this->extractElements($policy);
    return new Policy($action, $methods, $pathex, collect($children));
  }

  /**
   * Check whether an HTTP method is covered by a policy.
   *
   * A `*` policy accepts any method listed in {@see Parser::METHODS};
   * otherwise the method must appear in the policy's method list.
   *
   * @param  Policy  $policy  Policy to check against.
   * @param  string  $method  Request HTTP method, e.g. `GET`.
   * @return bool True when the method is covered.
   */
  protected function methodMatches(Policy $policy, string $method)
  {
    //If policy is * (any method)
    if ($policy->methods === '*') {
      //Make sure method is at least valid
      if (preg_match("/$method/", self::METHODS)===1) return true;
    }
    //Otherwise, if the policy contains propper method (eg: GET, POST...)
    else
    {
      //Make sure the method maches one in the policy
      if (preg_match("/$method/", $policy->methods)===1) return true;
    }
    return false;
  }

  /**
   * Check whether a URI matches the policy's pathex.
   *
   * @param  Policy  $policy  Policy to check against.
   * @param  string  $uri  Request URI, e.g. `/admin/users`.
   * @return bool True when the URI matches.
   */
  protected function uriMatches(Policy $policy, string $uri)
  {
    if (preg_match($policy->pathex, $uri) === 1) return true;
    return false;
  }

  /**
   * Check whether a request (method + URI) is covered by a policy.
   *
   * Only this policy is evaluated; its children and its allow/deny action are not considered.
   *
   * @param  Policy  $policy  Policy to check against.
   * @param  string  $method  Request HTTP method.
   * @param  string  $uri  Request URI.
   * @return bool True when both the method and the URI match.
   */
  public function isMatch(Policy $policy, string $method, string $uri): bool
  { 
    if (!$this->methodMatches($policy, $method)) return false;

    return $this->uriMatches($policy, $uri);
  }
}