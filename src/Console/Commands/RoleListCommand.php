<?php

declare(strict_types=1);

namespace Marcohern\Jwtauthorize\Console\Commands;

use Illuminate\Console\Command;
use Marcohern\Jwtauthorize\PolicyManager;

class RoleListCommand extends Command
{
    /**
     * The command signature.
     */
    protected $signature = 'jwta:role:list';

    /**
     * The command description.
     */
    protected $description = 'List all roles.';

    /**
     * Execute the console command.
     */
    public function handle(PolicyManager $manager): int
    {
        $roles = $manager->all();

        if ($roles->isEmpty()) {
            $this->info('No roles found.');

            return self::SUCCESS;
        }

        $roles->each(fn (string $role) => $this->line($role));

        return self::SUCCESS;
    }
}
