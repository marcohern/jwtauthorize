<?php

declare(strict_types=1);

namespace Marcohern\Jwtauthorize\Console\Commands;

use Illuminate\Console\Command;
use InvalidArgumentException;
use JsonException;
use Marcohern\Jwtauthorize\Exceptions\JwtAuthorizeException;

/**
 * Base class for the `jwta:role:*` commands that act on one role.
 */
abstract class RoleCommand extends Command
{
    /**
     * Run a role action, turning package, input and JSON errors into a failed command.
     *
     * @param  callable(): string  $action  Runs the action and returns the success message.
     * @return int The command exit code.
     */
    protected function runAction(callable $action): int
    {
        try {
            $this->info($action());

            return self::SUCCESS;
        } catch (JwtAuthorizeException|InvalidArgumentException|JsonException $e) {
            $this->error($e->getMessage());

            return self::FAILURE;
        }
    }
}
