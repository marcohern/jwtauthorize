<?php

declare(strict_types=1);

namespace Marcohern\Jwtauthorize\Console\Commands;

use Marcohern\Jwtauthorize\PolicyBuilder;
use Marcohern\Jwtauthorize\PolicyManager;

class RoleUpdateCommand extends RoleCommand
{
    /**
     * The command signature.
     */
    protected $signature = 'jwta:role:update
        {role : The role name}
        {policies?* : Policy strings, e.g. "allow GET /.*/"}
        {--file= : JSON file with the policies, supports nesting}';

    /**
     * The command description.
     */
    protected $description = 'Replace the policies of an existing role.';

    /**
     * Execute the console command.
     */
    public function handle(PolicyManager $manager, PolicyBuilder $builder): int
    {
        return $this->runAction(function () use ($manager, $builder) {
            $role = $this->argument('role');
            $manager->update($role, $this->policies($builder));

            return "Role [$role] updated.";
        });
    }
}
