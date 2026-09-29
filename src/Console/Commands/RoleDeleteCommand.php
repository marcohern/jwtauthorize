<?php

declare(strict_types=1);

namespace Marcohern\Jwtauthorize\Console\Commands;

use Marcohern\Jwtauthorize\PolicyManager;

class RoleDeleteCommand extends RoleCommand
{
    /**
     * The command signature.
     */
    protected $signature = 'jwta:role:delete
        {role : The role name}
        {--force : Delete without asking for confirmation}';

    /**
     * The command description.
     */
    protected $description = 'Delete a role.';

    /**
     * Execute the console command.
     */
    public function handle(PolicyManager $manager): int
    {
        return $this->runAction(function () use ($manager) {
            $role = $this->role();

            if (! $this->option('force') && $this->input->isInteractive() && ! $this->confirm("Delete role [$role]?")) {
                return 'Cancelled.';
            }

            $manager->delete($role);

            return "Role [$role] deleted.";
        });
    }
}
