<?php

declare(strict_types=1);

namespace Marcohern\Jwtauthorize\Console\Commands;

use Illuminate\Console\Command;
use Illuminate\Support\Collection;
use InvalidArgumentException;
use JsonException;
use Marcohern\Jwtauthorize\Exceptions\JwtaParserException;
use Marcohern\Jwtauthorize\Exceptions\JwtAuthorizeException;
use Marcohern\Jwtauthorize\Policy;
use Marcohern\Jwtauthorize\PolicyBuilder;

/**
 * Base class for the `jwta:role:*` commands.
 */
abstract class RoleCommand extends Command
{
    /**
     * Build the policies given as `policies*` arguments or in a `--file` JSON file.
     *
     * Arguments are policy strings, e.g. `"allow GET /.*\/"`. The file holds
     * the shape accepted by {@see PolicyBuilder::fromList()}, so it can nest
     * policies: `{"deny * /\/admin(\/.*)?/": ["allow GET /\/admin\/reports/"]}`.
     *
     * @return Collection<int, Policy> The built, validated policies.
     *
     * @throws InvalidArgumentException When both or neither inputs are given, or the file cannot be read.
     * @throws JsonException When the file is not valid JSON.
     * @throws JwtaParserException When a policy is invalid.
     */
    protected function policies(PolicyBuilder $builder): Collection
    {
        $arguments = $this->argument('policies');
        $file = $this->option('file');

        if (! is_array($arguments) || ($file !== null && ! is_string($file))) {
            throw new InvalidArgumentException('Invalid policies input.');
        }

        if ($file !== null && $arguments !== []) {
            throw new InvalidArgumentException('Pass policies as arguments or with --file, not both.');
        }

        if ($file === null && $arguments === []) {
            throw new InvalidArgumentException('No policies given. Pass them as arguments or with --file.');
        }

        if ($file === null) {
            return $builder->fromList($arguments);
        }

        if (! is_file($file) || ($json = file_get_contents($file)) === false) {
            throw new InvalidArgumentException("Policy file [$file] cannot be read.");
        }
        $policies = json_decode($json, true, flags: JSON_THROW_ON_ERROR);

        if (! is_array($policies)) {
            throw new InvalidArgumentException("Policy file [$file] must hold a JSON list or object.");
        }

        return $builder->fromList($policies);
    }

    /**
     * Get the `role` argument.
     *
     * @throws InvalidArgumentException When the argument is not a string.
     */
    protected function role(): string
    {
        $role = $this->argument('role');

        if (! is_string($role)) {
            throw new InvalidArgumentException('Invalid role name.');
        }

        return $role;
    }

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
