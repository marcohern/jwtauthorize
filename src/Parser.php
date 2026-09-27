<?php
declare(strict_types=1);

namespace Marcohern\Jwtauthorize;

use Illuminate\Support\Collection;
use Illuminate\Support\Str;
use Marcohern\Jwtauthorize\Exceptions\JwtaParserException;


class Parser {
  private const ACTIONS = 'allow|deny';
  private const METHODS = 'GET|POST|PUT|PATCH|DELETE|HEAD|OPTIONS|CONNECT|TRACE';
  private const METHOD_LIST = '(('.self::METHODS.'),)*('.self::METHODS.')';
  private const REGEX = '/^('.self::ACTIONS.') (\*|'.self::METHOD_LIST.') ([^\s]+)$/';

  
  /**
   * Create a new class instance.
   */
  public function __construct()
  {
      //
  }

  public function isValid(string $policy): bool
  {
    return Str::isMatch(self::REGEX, $policy);
  }

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

  public function extract(string $policy, Collection|array $children = []): Policy
  {
    list($action, $methods, $pathex) = $this->extractElements($policy);
    return new Policy($action, $methods, $pathex, collect($children));
  }

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

  protected function uriMatches(Policy $policy, string $uri)
  {
    if (preg_match($policy->pathex, $uri) === 1) return true;
    return false;
  }

  public function isMatch(Policy $policy, string $method, string $uri): bool
  { 
    if (!$this->methodMatches($policy, $method)) return false;

    return $this->uriMatches($policy, $uri);
  }
}