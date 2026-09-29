<?php

declare(strict_types=1);

namespace Marcohern\Jwtauthorize;

use Marcohern\Jwtauthorize\Evaluation\Evaluation;
use Marcohern\Jwtauthorize\Evaluation\EvaluationNode;
use Marcohern\Jwtauthorize\Exceptions\JwtaParserException;

/**
 * Decides whether policies allow a request, and records how.
 *
 * This is the decision used by the {@see Middleware\Authorize} middleware and
 * by the role testers, so they always agree:
 *  - A policy matches when it covers the method and its pathex matches the whole path.
 *  - A matching policy's children refine it; when none of them match, the policy itself decides.
 *  - Among matching siblings, the first `deny` decides at once; otherwise the first `allow` does.
 *  - When no policy matches, the request is not allowed.
 */
class PolicyEvaluator
{
    /**
     * @param  Parser  $parser  Parser used to match policies against the request.
     */
    public function __construct(private readonly Parser $parser) {}

    /**
     * Evaluate policies against a request.
     *
     * @param  iterable<Policy>  $policies  Top-level policies.
     * @param  string  $method  Request HTTP method, e.g. `GET`.
     * @param  string  $path  Decoded request path, see {@see PolicyEvaluator::normalizePath()}.
     * @return Evaluation The decision, with the evaluated tree.
     *
     * @throws JwtaParserException When a policy fails to evaluate.
     */
    public function evaluate(iterable $policies, string $method, string $path): Evaluation
    {
        $nodes = EvaluationNode::tree($policies);
        $chain = $this->decide($nodes, $method, $path) ?? [];

        foreach ($chain as $node) {
            $node->onDecisionPath = true;
        }

        if ($chain !== []) {
            $chain[array_key_last($chain)]->decides = true;
        }

        return new Evaluation($method, $path, $nodes, $chain);
    }

    /**
     * Turn a path or URL into the path the middleware evaluates.
     *
     * Drops the scheme, host, query string and fragment, decodes it, and keeps
     * exactly one leading slash, like `'/'.ltrim($request->decodedPath(), '/')`.
     * For example `https://example.com/%61dmin/users/?page=2` becomes `/admin/users`.
     */
    public static function normalizePath(string $input): string
    {
        $input = trim($input);
        $path = preg_match('#^[a-z][a-z0-9+.-]*://#i', $input) === 1
            ? (string) parse_url($input, PHP_URL_PATH)
            : (string) preg_replace('/[?#].*$/s', '', $input);

        return '/'.ltrim(rawurldecode(trim($path, '/')), '/');
    }

    /**
     * Find the chain of nodes that decides the request among siblings.
     *
     * @param  list<EvaluationNode>  $nodes  Sibling nodes.
     * @param  string  $method  Request HTTP method.
     * @param  string  $path  Decoded request path.
     * @return list<EvaluationNode>|null From one of the siblings down to the deciding node, or null when none match.
     *
     * @throws JwtaParserException When a policy fails to evaluate.
     */
    protected function decide(array $nodes, string $method, string $path): ?array
    {
        $decision = null;
        foreach ($nodes as $node) {
            $node->methodMatched = $this->parser->methodMatches($node->policy, $method);
            $node->pathMatched = $node->methodMatched ? $this->parser->uriMatches($node->policy, $path) : null;

            if (! $node->methodMatched || ! $node->pathMatched) {
                $node->status = EvaluationNode::UNMATCHED;

                continue;
            }

            $node->status = EvaluationNode::MATCHED;
            $chain = [$node, ...($this->decide($node->children, $method, $path) ?? [])];

            if ($chain[array_key_last($chain)]->policy->action === 'deny') {
                return $chain;
            }
            $decision ??= $chain;
        }

        return $decision;
    }
}
