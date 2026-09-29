<?php

declare(strict_types=1);

namespace Marcohern\Jwtauthorize\Console\Commands;

use JsonException;
use Marcohern\Jwtauthorize\Exceptions\JwtAuthorizeException;
use Marcohern\Jwtauthorize\PolicyManager;

class RoleShowCommand extends RoleCommand
{
    /**
     * The command signature.
     */
    protected $signature = 'jwta:role:show {role : The role name}';

    /**
     * The command description.
     */
    protected $description = 'Show the policies of a role as JSON.';

    /**
     * Execute the console command.
     */
    public function handle(PolicyManager $manager): int
    {
        try {
            $policies = $manager->get($this->argument('role'));
        } catch (JwtAuthorizeException|JsonException $e) {
            $this->error($e->getMessage());

            return self::FAILURE;
        }

        $this->line(json_encode($policies, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES | JSON_THROW_ON_ERROR));

        return self::SUCCESS;
    }
}
