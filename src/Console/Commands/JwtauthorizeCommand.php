<?php

declare(strict_types=1);

namespace Jwtauthorize\Jwtauthorize\Console\Commands;

use Illuminate\Console\Command;

class JwtauthorizeCommand extends Command
{
    /**
     * The command signature.
     */
    protected $signature = 'jwtauthorize:placeholder';

    /**
     * The command description.
     */
    protected $description = 'Placeholder Artisan command shipped by the package jwtauthorize.';

    /**
     * Execute the console command.
     */
    public function handle(): int
    {
        $this->line('Jwtauthorize placeholder command executed.');

        return self::SUCCESS;
    }
}
