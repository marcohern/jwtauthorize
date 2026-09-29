<?php

declare(strict_types=1);

namespace Marcohern\Jwtauthorize\Console\Commands;

use JsonException;
use Marcohern\Jwtauthorize\Evaluation\EvaluationNode;
use Marcohern\Jwtauthorize\Exceptions\JwtaParserException;
use Marcohern\Jwtauthorize\Exceptions\JwtAuthorizeException;
use Marcohern\Jwtauthorize\Parser;
use Marcohern\Jwtauthorize\PolicyEvaluator;
use Marcohern\Jwtauthorize\PolicyManager;
use Symfony\Component\Console\Formatter\OutputFormatter;

class RoleTestCommand extends RoleCommand
{
    /**
     * The command signature.
     */
    protected $signature = 'jwta:role:test
        {role : The role name}
        {method : HTTP method, e.g. GET}
        {path : Request path or URL, e.g. /api/users/1}';

    /**
     * The command description.
     */
    protected $description = 'Test whether a role allows a request, and show which policies decided. Exits 0 when allowed, 1 otherwise.';

    /**
     * Execute the console command.
     */
    public function handle(PolicyManager $manager, PolicyEvaluator $evaluator, Parser $parser): int
    {
        $role = $this->argument('role');
        $method = strtoupper($this->argument('method'));
        $path = PolicyEvaluator::normalizePath($this->argument('path'));
        $request = OutputFormatter::escape("$method $path  (role: $role)");

        if (! in_array($method, $parser->methods(), true)) {
            $this->error("Method [$method] invalid. Use one of: ".implode(', ', $parser->methods()).'.');

            return self::FAILURE;
        }

        try {
            $evaluation = $evaluator->evaluate($manager->get($role), $method, $path);
        } catch (JwtaParserException $e) {
            $this->line("<fg=red;options=bold>DENIED</>  $request");
            $this->error('A policy failed to evaluate, so the middleware fails closed: '.$e->getMessage());

            return self::FAILURE;
        } catch (JwtAuthorizeException|JsonException $e) {
            $this->error($e->getMessage());

            return self::FAILURE;
        }

        $verdict = $evaluation->allowed() ? '<fg=green;options=bold>ALLOWED</>' : '<fg=red;options=bold>DENIED</>';
        $this->line("$verdict  $request");

        if ($evaluation->decidingNode() === null) {
            $this->line('No policy matched.');
        }
        $this->newLine();
        $this->printNodes($evaluation->nodes, 0);
        $this->newLine();
        $this->line('<fg=gray>✓ matched  ✗ no match  · not checked  ▶ decision path</>');

        return $evaluation->allowed() ? self::SUCCESS : self::FAILURE;
    }

    /**
     * Print evaluated nodes, one per line, indented by depth.
     *
     * @param  list<EvaluationNode>  $nodes
     */
    protected function printNodes(array $nodes, int $depth): void
    {
        foreach ($nodes as $node) {
            $mark = match ($node->status) {
                EvaluationNode::MATCHED => '<fg=green>✓</>',
                EvaluationNode::UNMATCHED => '<fg=red>✗</>',
                default => '<fg=gray>·</>',
            };
            $path = $node->onDecisionPath ? '▶' : ' ';
            $policy = OutputFormatter::escape("{$node->policy->action} {$node->policy->methods} {$node->policy->pathex}");
            $suffix = $node->decides ? '  <options=bold>← decides</>' : '';

            $this->line("$mark $path ".str_repeat('  ', $depth).$policy.$suffix);
            $this->printNodes($node->children, $depth + 1);
        }
    }
}
