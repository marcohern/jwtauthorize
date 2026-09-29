<?php

declare(strict_types=1);

namespace Marcohern\Jwtauthorize;

use Illuminate\Support\Collection;
use Marcohern\Jwtauthorize\Exceptions\JwtaParserException;
use stdClass;

/**
 * Builds {@see Policy} trees from raw policy definitions.
 *
 * Accepts policy strings (parsed with the injected {@see Parser}), associative
 * arrays and stdClass objects with `action`, `methods`, `pathex` and optional
 * `children` keys (role files and decoded JWT claims, see {@see Policy::toArray()}),
 * existing Policy instances, and nested lists of any of those.
 *
 * Every definition is validated with {@see Parser}, whatever its shape.
 */
class PolicyBuilder
{
    /**
     * @param  Parser  $parser  Parser used to validate definitions and parse policy strings.
     */
    public function __construct(public Parser $parser) {}

    /**
     * Build a policy from an associative array with `action`, `methods`, `pathex` and optional `children` keys.
     *
     * @param  array<mixed>  $policy  Array describing the policy.
     * @param  Collection<int|string, mixed>|array<int|string, mixed>  $children  Extra raw child definitions, see {@see PolicyBuilder::fromList()}.
     * @return Policy The built policy, children included.
     *
     * @throws JwtaParserException When a key is missing or not a string, or the policy is invalid.
     */
    protected function fromArray(array $policy, Collection|array $children): Policy
    {
        $action = $policy['action'] ?? null;
        $methods = $policy['methods'] ?? null;
        $pathex = $policy['pathex'] ?? null;

        if (! is_string($action) || ! is_string($methods) || ! is_string($pathex)) {
            throw new JwtaParserException('Policy invalid.');
        }
        $this->parser->validate($action, $methods, $pathex);

        $ownChildren = $policy['children'] ?? [];

        if (! is_array($ownChildren) && ! $ownChildren instanceof Collection) {
            throw new JwtaParserException('Policy invalid.');
        }

        return new Policy($action, $methods, $pathex, $this->fromList($ownChildren)->concat($this->fromList($children)));
    }

    /**
     * Build a policy from a policy string.
     *
     * @param  string  $policy  Policy string, e.g. `deny * /\/admin(\/.*)?/`.
     * @param  Collection<int|string, mixed>|array<int|string, mixed>  $children  Raw child definitions, see {@see PolicyBuilder::fromList()}.
     * @return Policy The built policy, children included.
     *
     * @throws JwtaParserException When the string is not a valid policy.
     */
    protected function fromString(string $policy, Collection|array $children): Policy
    {
        return $this->parser->extract($policy, $this->fromList($children));
    }

    /**
     * Build a policy from any supported definition.
     *
     * `$children` are appended to the definition's own children. A Policy
     * without extra children is returned unchanged.
     *
     * @param  mixed  $policy  Policy, stdClass, associative array or policy string.
     * @param  Collection<int|string, mixed>|array<int|string, mixed>  $children  Raw child definitions, see {@see PolicyBuilder::fromList()}.
     * @return Policy The built policy.
     *
     * @throws JwtaParserException When the definition type is not supported or the policy is invalid.
     */
    public function from(mixed $policy, Collection|array $children = []): Policy
    {
        if ($policy instanceof Policy) {
            if (count($children) === 0) {
                return $policy;
            }

            return new Policy($policy->action, $policy->methods, $policy->pathex, $policy->children->concat($this->fromList($children)));
        }

        if ($policy instanceof stdClass) {
            return $this->fromArray((array) $policy, $children);
        }

        if (is_array($policy) && ! array_is_list($policy)) {
            return $this->fromArray($policy, $children);
        }

        if (is_string($policy)) {
            return $this->fromString($policy, $children);
        }

        throw new JwtaParserException('Policy invalid. Unable to build a policy from ['.get_debug_type($policy).'].');
    }

    /**
     * Build a list of policies, recursively.
     *
     * Integer keys hold a policy definition (see {@see PolicyBuilder::from()}).
     * String keys hold a policy string whose value is the list of its children:
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
     * @throws JwtaParserException When a definition is not supported or a policy is invalid.
     */
    public function fromList(Collection|array $policies): Collection
    {
        $list = [];
        foreach ($policies as $key => $value) {
            if (is_int($key)) {
                $list[] = $this->from($value);

                continue;
            }

            if (! is_array($value) && ! $value instanceof Collection) {
                throw new JwtaParserException("Policy invalid. Children of [$key] must be a list.");
            }
            $list[] = $this->from($key, $value);
        }

        return collect($list);
    }
}
