<?php

declare(strict_types=1);

namespace Marcohern\Jwtauthorize\Console\Commands;

use Marcohern\Jwtauthorize\PolicyBuilder;
use Marcohern\Jwtauthorize\PolicyManager;

class RoleCreateCommand extends RoleCommand
{
    /**
     * The command signature.
     */
    protected $signature = 'jwta:role:create
        {role : The role name (letters, digits, - and _)}
        {policies?* : Policy strings, e.g. "allow GET /.*/"}
        {--file= : JSON file with the policies, supports nesting}';

    /**
     * The command description.
     */
    protected $description = 'Create a role with a list of policies.';

    /**
     * Execute the console command.
     */
    public function handle(PolicyManager $manager, PolicyBuilder $builder): int
    {
        return $this->runAction(function () use ($manager, $builder) {
            $role = $this->argument('role');
            $manager->create($role, $this->policies($builder));

            return "Role [$role] created.";
        });
    }
}
