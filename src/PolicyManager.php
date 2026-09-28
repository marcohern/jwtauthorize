<?php
declare(strict_types=1);

namespace Marcohern\Jwtauthorize;

use Illuminate\Support\Collection;
use Illuminate\Support\Facades\Storage;
use Marcohern\Jwtauthorize\Exceptions\JwtaRoleException;

/**
 * Manages roles: named lists of policies stored as JSON files.
 *
 * Each role is stored in private app storage (the `local` disk) as
 * `jwta/roles/{role}.json`. The file holds the serialized policies
 * (see {@see Policy::jsonSerialize()}), children included:
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
class PolicyManager {
  /**
   * Storage disk holding the role files.
   */
  private const DISK = 'local';

  /**
   * Folder, inside the disk, holding the role files.
   */
  private const PATH = 'jwta/roles';

  /**
   * Allowed role name pattern; also keeps role files inside {@see PolicyManager::PATH}.
   */
  private const ROLE_REGEX = '/^[A-Za-z0-9_-]+$/';

  /**
   * @param  PolicyBuilder  $builder  Builder used to load policies from role files.
   */
  public function __construct(private readonly PolicyBuilder $builder)
  {
  }

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
    if ($this->exists($role)) throw new JwtaRoleException("Role [$role] already exists.");
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
    Storage::disk(self::DISK)->delete($this->path($role));
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
    return Storage::disk(self::DISK)->exists($this->path($role));
  }

  /**
   * Load the policies of a role.
   *
   * @param  string  $role  Role name.
   * @return Collection<int, Policy> The role's policies.
   *
   * @throws JwtaRoleException When the role name is invalid or the role does not exist.
   * @throws \JsonException When the role file is not valid JSON.
   */
  public function get(string $role): Collection
  {
    $this->ensureExists($role);
    $json = Storage::disk(self::DISK)->get($this->path($role));
    $policies = json_decode($json, flags: JSON_THROW_ON_ERROR);
    return $this->builder->fromList($policies);
  }

  /**
   * List the names of all roles.
   *
   * @return Collection<int, string> Role names, sorted.
   */
  public function all(): Collection
  {
    return collect(Storage::disk(self::DISK)->files(self::PATH))
      ->filter(fn (string $file) => str_ends_with($file, '.json'))
      ->map(fn (string $file) => basename($file, '.json'))
      ->sort()
      ->values();
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
    if (preg_match(self::ROLE_REGEX, $role) !== 1) throw new JwtaRoleException("Role name [$role] invalid.");
    return self::PATH."/$role.json";
  }

  /**
   * @param  string  $role  Role name.
   *
   * @throws JwtaRoleException When the role does not exist.
   */
  protected function ensureExists(string $role): void
  {
    if (!$this->exists($role)) throw new JwtaRoleException("Role [$role] not found.");
  }

  /**
   * Write the policies to the role file.
   *
   * @param  string  $role  Role name.
   * @param  Collection<int, Policy>  $policies  The role's policies.
   */
  protected function write(string $role, Collection $policies): void
  {
    $json = json_encode($policies->values(),JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES | JSON_THROW_ON_ERROR);
    Storage::disk(self::DISK)->put($this->path($role), $json);
  }
}
