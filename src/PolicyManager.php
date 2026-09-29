<?php

declare(strict_types=1);

namespace Marcohern\Jwtauthorize;

use Illuminate\Contracts\Filesystem\Filesystem;
use Illuminate\Support\Collection;
use Illuminate\Support\Facades\Storage;
use JsonException;
use Marcohern\Jwtauthorize\Exceptions\JwtaParserException;
use Marcohern\Jwtauthorize\Exceptions\JwtaRoleException;

/**
 * Manages roles: named lists of policies stored as JSON files.
 *
 * Each role is stored on the `jwtauthorize.roles.disk` disk (`local` by
 * default) as `{jwtauthorize.roles.path}/{role}.json` (`jwta/roles/{role}.json`
 * by default). The file holds the serialized policies (see {@see Policy::toArray()}),
 * children included:
 *
 * ```json
 * [
 *   {
 *     "action": "deny",
 *     "methods": "*",
 *     "pathex": "/\/admin(\/.*)?/",
 *     "children": [
 *       { "action": "allow", "methods": "GET", "pathex": "/\/admin\/reports/", "children": [] }
 *     ]
 *   }
 * ]
 * ```
 */
class PolicyManager
{
    /**
     * Allowed role name pattern; also keeps role files inside the roles folder.
     */
    private const ROLE_REGEX = '/^[A-Za-z0-9_-]+$/';

    /**
     * @param  PolicyBuilder  $builder  Builder used to load policies from role files.
     */
    public function __construct(private readonly PolicyBuilder $builder) {}

    /**
     * Create a new role.
     *
     * @param  string  $role  Role name (letters, digits, `-` and `_`).
     * @param  Collection<int, Policy>  $policies  The role's policies.
     *
     * @throws JwtaRoleException When the role name is invalid or the role already exists.
     */
    public function create(string $role, Collection $policies): void
    {
        if ($this->exists($role)) {
            throw new JwtaRoleException("Role [$role] already exists.");
        }
        $this->write($role, $policies);
    }

    /**
     * Replace the policies of an existing role.
     *
     * @param  string  $role  Role name.
     * @param  Collection<int, Policy>  $policies  The role's new policies.
     *
     * @throws JwtaRoleException When the role name is invalid or the role does not exist.
     */
    public function update(string $role, Collection $policies): void
    {
        $this->ensureExists($role);
        $this->write($role, $policies);
    }

    /**
     * Delete an existing role.
     *
     * @param  string  $role  Role name.
     *
     * @throws JwtaRoleException When the role name is invalid or the role does not exist.
     */
    public function delete(string $role): void
    {
        $this->ensureExists($role);
        $this->disk()->delete($this->path($role));
    }

    /**
     * Check whether a role exists.
     *
     * @param  string  $role  Role name.
     * @return bool True when the role file exists.
     *
     * @throws JwtaRoleException When the role name is invalid.
     */
    public function exists(string $role): bool
    {
        return $this->disk()->exists($this->path($role));
    }

    /**
     * Load the policies of a role.
     *
     * @param  string  $role  Role name.
     * @return Collection<int, Policy> The role's policies.
     *
     * @throws JwtaRoleException When the role name is invalid, the role does not exist, or its file is not a list.
     * @throws JsonException When the role file is not valid JSON.
     * @throws JwtaParserException When a stored policy is invalid.
     */
    public function get(string $role): Collection
    {
        $this->ensureExists($role);
        $json = $this->disk()->get($this->path($role));
        $policies = json_decode((string) $json, true, flags: JSON_THROW_ON_ERROR);

        if (! is_array($policies)) {
            throw new JwtaRoleException("Role [$role] file is not a list of policies.");
        }

        return $this->builder->fromList($policies);
    }

    /**
     * Get the policies of one or more roles in the shape carried by the JWT claim.
     *
     * Pass the result as the claim when issuing a token, e.g.
     * `auth()->claims(['scope' => $manager->claim('editor')])->attempt($credentials)`.
     * The policies of every role are concatenated; as siblings, a matching `deny`
     * from any role wins over an `allow` from another.
     *
     * @param  string  ...$roles  Role names.
     * @return list<array{action: string, methods: string, pathex: string, children: list<array<string, mixed>>}> The policies as plain arrays.
     *
     * @throws JwtaRoleException When a role name is invalid or a role does not exist.
     * @throws JsonException When a role file is not valid JSON.
     */
    public function claim(string ...$roles): array
    {
        return array_values(collect($roles)
            ->flatMap(fn (string $role) => $this->get($role))
            ->map(fn (Policy $policy) => $policy->toArray())
            ->all());
    }

    /**
     * List the names of all roles.
     *
     * @return Collection<int, string> Role names, sorted.
     */
    public function all(): Collection
    {
        return collect($this->disk()->files($this->directory()))
            ->filter(fn (string $file) => str_ends_with($file, '.json'))
            ->map(fn (string $file) => basename($file, '.json'))
            ->sort()
            ->values();
    }

    /**
     * Get the disk holding the role files.
     */
    protected function disk(): Filesystem
    {
        return Storage::disk(config('jwtauthorize.roles.disk', 'local'));
    }

    /**
     * Get the folder, inside the disk, holding the role files.
     */
    protected function directory(): string
    {
        return rtrim((string) config('jwtauthorize.roles.path', 'jwta/roles'), '/');
    }

    /**
     * Get the storage path of a role file.
     *
     * @param  string  $role  Role name.
     * @return string Path relative to the disk root, e.g. `jwta/roles/admin.json`.
     *
     * @throws JwtaRoleException When the role name is invalid.
     */
    protected function path(string $role): string
    {
        if (preg_match(self::ROLE_REGEX, $role) !== 1) {
            throw new JwtaRoleException("Role name [$role] invalid.");
        }

        return $this->directory()."/$role.json";
    }

    /**
     * @param  string  $role  Role name.
     *
     * @throws JwtaRoleException When the role does not exist.
     */
    protected function ensureExists(string $role): void
    {
        if (! $this->exists($role)) {
            throw new JwtaRoleException("Role [$role] not found.");
        }
    }

    /**
     * Write the policies to the role file.
     *
     * @param  string  $role  Role name.
     * @param  Collection<int, Policy>  $policies  The role's policies.
     */
    protected function write(string $role, Collection $policies): void
    {
        $json = json_encode($policies->values(), JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES | JSON_THROW_ON_ERROR);
        $this->disk()->put($this->path($role), $json);
    }
}
