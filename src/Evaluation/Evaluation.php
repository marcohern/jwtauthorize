<?php

declare(strict_types=1);

namespace Marcohern\Jwtauthorize\Evaluation;

use Marcohern\Jwtauthorize\PolicyEvaluator;

/**
 * The outcome of evaluating a policy tree against a request, with its trace.
 *
 * @see PolicyEvaluator::evaluate()
 */
final class Evaluation
{
    /**
     * @param  string  $method  Evaluated HTTP method.
     * @param  string  $path  Evaluated, normalized request path.
     * @param  list<EvaluationNode>  $nodes  The evaluated tree.
     * @param  list<EvaluationNode>  $chain  From a top-level policy down to the deciding policy; empty when none matched.
     */
    public function __construct(
        public readonly string $method,
        public readonly string $path,
        public readonly array $nodes,
        public readonly array $chain,
    ) {}

    /**
     * Whether the request is allowed: a policy matched, and the deciding one allows.
     */
    public function allowed(): bool
    {
        return $this->decidingNode()?->policy->action === 'allow';
    }

    /**
     * The node of the policy that decided the request, or null when no policy matched.
     */
    public function decidingNode(): ?EvaluationNode
    {
        return $this->chain === [] ? null : $this->chain[array_key_last($this->chain)];
    }
}
