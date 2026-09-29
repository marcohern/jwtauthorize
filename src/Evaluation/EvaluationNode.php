<?php

declare(strict_types=1);

namespace Marcohern\Jwtauthorize\Evaluation;

use Marcohern\Jwtauthorize\Policy;
use Marcohern\Jwtauthorize\PolicyEvaluator;

/**
 * The result of evaluating one policy of a tree against a request.
 *
 * Built and filled in by {@see PolicyEvaluator};
 * treat it as read-only.
 */
final class EvaluationNode
{
    /**
     * Both the method and the path matched; the children were evaluated.
     */
    public const string MATCHED = 'matched';

    /**
     * The method or the path did not match; the children were not evaluated.
     */
    public const string UNMATCHED = 'unmatched';

    /**
     * Never checked: its parent did not match, or a `deny` decided before it was reached.
     */
    public const string NOT_EVALUATED = 'not_evaluated';

    /**
     * One of the status constants.
     */
    public string $status = self::NOT_EVALUATED;

    /**
     * Whether the request method is covered, or null when not checked.
     */
    public ?bool $methodMatched = null;

    /**
     * Whether the path matches the pathex, or null when not checked (the method did not match).
     */
    public ?bool $pathMatched = null;

    /**
     * Whether the node is on the chain from a top-level policy to the deciding policy.
     */
    public bool $onDecisionPath = false;

    /**
     * Whether this is the policy that decided the request.
     */
    public bool $decides = false;

    /**
     * @param  Policy  $policy  The evaluated policy.
     * @param  list<EvaluationNode>  $children  Nodes of the policy's children.
     */
    public function __construct(
        public readonly Policy $policy,
        public readonly array $children = [],
    ) {}

    /**
     * Build the node tree for a list of policies, every node not evaluated.
     *
     * @param  iterable<Policy>  $policies
     * @return list<EvaluationNode>
     */
    public static function tree(iterable $policies): array
    {
        $nodes = [];
        foreach ($policies as $policy) {
            $nodes[] = new self($policy, self::tree($policy->children));
        }

        return $nodes;
    }
}
