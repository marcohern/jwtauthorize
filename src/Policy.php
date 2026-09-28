<?php
declare(strict_types=1);

namespace Marcohern\Jwtauthorize;

use Illuminate\Support\Collection;

/**
 * Immutable node of a policy tree.
 *
 * A policy either allows or denies requests whose HTTP method is listed in
 * {@see Policy::$methods} and whose URI matches {@see Policy::$pathex}.
 * Child policies are more specific rules nested under this one (e.g. allow
 * everything, but deny /admin).
 *
 * Instances are normally created by {@see PolicyBuilder} or {@see Parser::extract()}
 * from a policy string such as `deny POST /\/admin(\/.*)?/`.
 */
class Policy implements \JsonSerializable {
  /**
   * @var string Either `allow` or `deny`.
   */
  public readonly string $action;

  /**
   * @var string `*` for any method, or a comma separated list such as `GET,POST`.
   */
  public readonly string $methods;

  /**
   * @var string Regular expression, including delimiters, matched against the request URI (e.g. `/\/admin(\/.*)?/`).
   */
  public readonly string $pathex;

  /**
   * @var Collection<int, Policy> More specific policies nested under this one.
   */
  public readonly Collection $children;

  /**
   * @param  string  $action  Either `allow` or `deny`.
   * @param  string  $methods  `*` or a comma separated list of HTTP methods.
   * @param  string  $pathex  Regular expression, including delimiters, for the request URI.
   * @param  Collection<int, Policy>  $children  Already built child policies.
   */
  public function __construct(string $action, string $methods, string $pathex, Collection $children = new Collection)
  {
    $this->action = $action;
    $this->methods = $methods;
    $this->pathex = $pathex;
    $this->children = $children;
  }

  /**
   * Serialize the policy, and its children recursively, for `json_encode()`.
   *
   * @return array{action: string, methods: string, pathex: string, children: Collection<int, Policy>}
   */
  public function jsonSerialize(): array
  {
    return [
      'action' => $this->action,
      'methods' => $this->methods,
      'pathex' => $this->pathex,
      'children' => $this->children->values(),
    ];
  }
}
