<?php
declare(strict_types=1);

namespace Marcohern\Jwtauthorize;

use Illuminate\Support\Collection;
use Symfony\Component\HttpKernel\Exception\BadRequestHttpException;

/**
 * Builds {@see Policy} trees from raw policy definitions.
 *
 * Accepts policy strings (parsed with the injected {@see Parser}), stdClass
 * objects (e.g. decoded JSON), existing Policy instances, and nested lists
 * of any of those.
 */
class PolicyBuilder {
  /**
   * @param  Parser  $parser  Parser used to turn policy strings into policies.
   */
  public function __construct(public Parser $parser)
  {
  }

  /**
   * Build a policy from an object with `action`, `methods`, `pathex` and optional `children` properties.
   *
   * @param  \stdClass  $policy  Object describing the policy.
   * @return Policy The built policy, children included.
   */
  protected function fromStdClass(\stdClass $policy): Policy
  {
    $children = $this->fromList($policy->children ?? []);
    return new Policy($policy->action, $policy->methods, $policy->pathex, $children);
  }

  /**
   * Build a policy from an `[action, methods, pathex]` array.
   *
   * @param  array{0: string, 1: string, 2: string}  $policy  Policy components.
   * @param  Collection<int|string, mixed>|array<int|string, mixed>  $children  Raw child definitions, see {@see PolicyBuilder::fromList()}.
   * @return Policy The built policy, children included.
   */
  protected function fromArray(array $policy, Collection|array $children): Policy
  {
    return new Policy($policy[0], $policy[1], $policy[2], $this->fromList($children));
  }

  /**
   * Build a policy from a policy string.
   *
   * @param  string  $policy  Policy string, e.g. `deny * /\/admin(\/.*)?/`.
   * @param  Collection<int|string, mixed>|array<int|string, mixed>  $children  Raw child definitions, see {@see PolicyBuilder::fromList()}.
   * @return Policy The built policy, children included.
   *
   * @throws Exceptions\JwtaParserException When the string is not a valid policy.
   */
  protected function fromString(string $policy, Collection|array $children): Policy
  {
    return $this->parser->extract($policy, $this->fromList($children));
  }

  /**
   * Build a policy from any supported definition.
   *
   * A Policy instance is returned unchanged; `$children` is only used for policy strings.
   *
   * @param  Policy|\stdClass|string  $policy  Policy definition.
   * @param  Collection<int|string, mixed>|array<int|string, mixed>  $children  Raw child definitions, see {@see PolicyBuilder::fromList()}.
   * @return Policy The built policy.
   *
   * @throws BadRequestHttpException When the definition type is not supported.
   * @throws Exceptions\JwtaParserException When a policy string is invalid.
   */
  public function from($policy, Collection|array $children=[]): Policy
  {
    if ($policy instanceof Policy) return $policy;
    if ($policy instanceof \stdClass) return $this->fromStdClass($policy);
    if (is_string($policy)) return $this->fromString($policy,$children);
    throw new BadRequestHttpException('unable to cast ['.get_debug_type($policy).'] to type ['.Policy::class.']');
  }

  /**
   * Build a list of policies, recursively.
   *
   * Integer keys hold a policy definition without children. String keys hold
   * a policy string whose value is the list of its children:
   *
   * ```php
   * [
   *   'deny * /\/admin(\/.*)?/',
   *   'deny * /\/orgs(\/.*)?/' => [
   *     'allow * /\/orgs\/reports(\/.*)?/',
   *   ],
   * ]
   * ```
   *
   * @param  Collection<int|string, mixed>|array<int|string, mixed>  $policies  Raw policy definitions.
   * @return Collection<int, Policy> The built policies.
   *
   * @throws BadRequestHttpException When a definition type is not supported.
   * @throws Exceptions\JwtaParserException When a policy string is invalid.
   */
  public function fromList(Collection|array $policies): Collection
  {
    $list = [];
    foreach ($policies as $key => $value) {
      if (is_integer($key)) $list[] = $this->from($value);
      else if (is_string($key)) {
        $list[] = $this->from($key, $value);
      }
    }
    return collect($list);
  }

}
