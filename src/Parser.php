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

  public function extract(string $policy): array
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

  public function isMatch(Policy $policy, string $method, string $uri): bool
  {
    
    $actions = $policy->action;
    $methods = $policy->methods;
    $pathex  = $policy->pathex;
    
    $methodMatch = false;
    $pathsMatch = false;
    
    $methodMatchEval = preg_match("/$method/", $policy->methods, $matches);
    if ($methodMatchEval !== 1) return false;
    
    if ($methods == '*') $methodMatch = true;
    else if ($matches[0]==$method) $methodMatch = true;

    $pathMatchEval = preg_match($policy->pathex, $uri);
    if ($pathMatchEval === 1) $pathsMatch = true;

    if ($pathsMatch && $methodMatch) return true;
    return false;
  }
}