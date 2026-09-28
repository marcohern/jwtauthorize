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
   * Closing delimiter for each bracket-style regex delimiter.
   */
  private const BRACKETS = ['(' => ')', '{' => '}', '[' => ']', '<' => '>'];

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
    $itMatches = preg_match(self::REGEX, $policy, $groups);
    if ($itMatches === 1)
    {
      $pathex = $groups[6];
      set_error_handler(static fn() => true);
      $isInvalid = (@preg_match($pathex, 'x') === false);
      restore_error_handler();
      if ($isInvalid) throw new JwtaParserException('Path in policy invalid. ['.preg_last_error().'] '.preg_last_error_msg());
      return [$groups[1],$groups[2],$pathex];
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
   * otherwise the method must be one of the policy's listed methods.
   * Methods are compared exactly, so `GE` does not match `GET`.
   *
   * @param  Policy  $policy  Policy to check against.
   * @param  string  $method  Request HTTP method, e.g. `GET`.
   * @return bool True when the method is covered.
   */
  protected function methodMatches(Policy $policy, string $method): bool
  {
    $methods = $policy->methods === '*'
      ? explode('|', self::METHODS)
      : explode(',', $policy->methods);

    return in_array($method, $methods, true);
  }

  /**
   * Check whether a path matches the policy's pathex.
   *
   * The pathex must match the whole path: it is anchored at both ends, so
   * `/\/users/` matches `/users` but not `/users/1` or `/admin/users`.
   *
   * @param  Policy  $policy  Policy to check against.
   * @param  string  $uri  Decoded request path without query string, e.g. `/admin/users`.
   * @return bool True when the path matches.
   *
   * @throws JwtaParserException When the pathex is invalid or fails to evaluate
   *                             (e.g. hits the PCRE backtrack limit).
   */
  protected function uriMatches(Policy $policy, string $uri): bool
  {
    $result = @preg_match($this->anchor($policy->pathex), $uri);
    if ($result === false) throw new JwtaParserException('Path match failed. ['.preg_last_error().'] '.preg_last_error_msg());
    return $result === 1;
  }

  /**
   * Anchor a delimited regex so it only matches whole strings.
   *
   * `/\/users/i` becomes `/^(?:\/users)\z/i`.
   *
   * @param  string  $pathex  Delimited regular expression, optionally followed by flags.
   * @return string The anchored regular expression.
   *
   * @throws JwtaParserException When the pathex has no closing delimiter.
   */
  protected function anchor(string $pathex): string
  {
    $open = $pathex[0] ?? '';
    $close = self::BRACKETS[$open] ?? $open;
    $end = $open === '' ? false : strrpos($pathex, $close, 1);
    if ($end === false) throw new JwtaParserException('Path in policy invalid.');

    $body = substr($pathex, 1, $end - 1);
    $flags = substr($pathex, $end + 1);
    return $open.'^(?:'.$body.')\z'.$close.$flags;
  }

  /**
   * Check whether a request (method + URI) is covered by a policy.
   *
   * Only this policy is evaluated; its children and its allow/deny action are not considered.
   *
   * @param  Policy  $policy  Policy to check against.
   * @param  string  $method  Request HTTP method.
   * @param  string  $uri  Decoded request path without query string.
   * @return bool True when both the method and the path match.
   *
   * @throws JwtaParserException When the pathex is invalid or fails to evaluate.
   */
  public function isMatch(Policy $policy, string $method, string $uri): bool
  { 
    if (!$this->methodMatches($policy, $method)) return false;

    return $this->uriMatches($policy, $uri);
  }
}