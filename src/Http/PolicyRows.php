<?php

declare(strict_types=1);

namespace Marcohern\Jwtauthorize\Http;

use Illuminate\Support\Collection;
use Marcohern\Jwtauthorize\Exceptions\JwtaParserException;
use Marcohern\Jwtauthorize\Policy;
use Marcohern\Jwtauthorize\PolicyBuilder;

/**
 * Converts between a policy tree and the flat rows of the role form.
 *
 * Each row is one policy plus its `depth`: 0 for a top-level policy, and one
 * more than its parent for a child. Rows are in depth-first order, so a
 * policy's children follow it directly:
 *
 * ```php
 * [
 *   ['action' => 'deny',  'methods' => '*',   'pathex' => '/\/admin(\/.*)?/',  'depth' => 0],
 *   ['action' => 'allow', 'methods' => 'GET', 'pathex' => '/\/admin\/reports/', 'depth' => 1],
 * ]
 * ```
 */
class PolicyRows
{
    /**
     * @param  PolicyBuilder  $builder  Builder used to validate and build the policies.
     */
    public function __construct(private readonly PolicyBuilder $builder) {}

    /**
     * Build the policy tree from form rows.
     *
     * @param  list<array{action: string, methods: string, pathex: string, depth: int}>  $rows  Rows in depth-first order.
     * @return Collection<int, Policy> The top-level policies, children included.
     *
     * @throws JwtaParserException When a row skips a level or a policy is invalid.
     */
    public function toPolicies(array $rows): Collection
    {
        $index = 0;
        $tree = $this->nest($rows, $index, 0);

        if ($index < count($rows)) {
            throw new JwtaParserException('Policy invalid. The first policy must be at the top level.');
        }

        return $this->builder->fromList($tree);
    }

    /**
     * Flatten a policy tree into form rows, depth first.
     *
     * @param  Collection<int, Policy>  $policies  Policies to flatten.
     * @param  int  $depth  Depth of the given policies.
     * @return list<array{action: string, methods: string, pathex: string, depth: int}> The rows.
     */
    public function fromPolicies(Collection $policies, int $depth = 0): array
    {
        $rows = [];
        foreach ($policies as $policy) {
            $rows[] = ['action' => $policy->action, 'methods' => $policy->methods, 'pathex' => $policy->pathex, 'depth' => $depth];
            array_push($rows, ...$this->fromPolicies($policy->children, $depth + 1));
        }

        return $rows;
    }

    /**
     * Consume the rows at `$depth`, starting at `$index`, with their children.
     *
     * @param  list<array{action: string, methods: string, pathex: string, depth: int}>  $rows  All rows.
     * @param  int  $index  Next row to read; advanced past the consumed rows.
     * @param  int  $depth  Depth being read.
     * @return list<array{action: string, methods: string, pathex: string, children: list<array<string, mixed>>}> The nested definitions.
     *
     * @throws JwtaParserException When a row is more than one level deeper than the row above it.
     */
    protected function nest(array $rows, int &$index, int $depth): array
    {
        $nodes = [];
        while ($index < count($rows) && $rows[$index]['depth'] >= $depth) {
            if ($rows[$index]['depth'] > $depth) {
                throw new JwtaParserException('Policy invalid. A policy can only be one level deeper than the policy above it.');
            }

            $row = $rows[$index++];
            $nodes[] = [
                'action' => $row['action'],
                'methods' => $row['methods'],
                'pathex' => $row['pathex'],
                'children' => $this->nest($rows, $index, $depth + 1),
            ];
        }

        return $nodes;
    }
}
