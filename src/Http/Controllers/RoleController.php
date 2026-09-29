<?php

declare(strict_types=1);

namespace Marcohern\Jwtauthorize\Http\Controllers;

use Illuminate\Contracts\View\Factory;
use Illuminate\Contracts\View\View;
use Illuminate\Http\RedirectResponse;
use Illuminate\Http\Request;
use Illuminate\Support\Collection;
use Marcohern\Jwtauthorize\Exceptions\JwtaRoleException;
use Marcohern\Jwtauthorize\Http\PolicyRows;
use Marcohern\Jwtauthorize\Http\Requests\RoleRequest;
use Marcohern\Jwtauthorize\Policy;
use Marcohern\Jwtauthorize\PolicyManager;
use Throwable;

/**
 * Web pages to list, view, create, edit, reorder and delete roles.
 *
 * Routes are registered by the service provider when `jwtauthorize.ui.enabled`
 * is on, behind `jwtauthorize.ui.middleware` and the `jwtauthorize.manage` gate.
 */
class RoleController
{
    /**
     * @param  PolicyManager  $manager  Role storage.
     * @param  PolicyRows  $rows  Converts between policy trees and form rows.
     * @param  Factory  $views  Renders the package views.
     */
    public function __construct(
        private readonly PolicyManager $manager,
        private readonly PolicyRows $rows,
        private readonly Factory $views,
    ) {}

    /**
     * List every role with its number of top-level policies.
     */
    public function index(): View
    {
        $roles = $this->manager->all()->mapWithKeys(function (string $role): array {
            try {
                return [$role => $this->manager->get($role)->count()];
            } catch (Throwable) {
                return [$role => null];
            }
        });

        return $this->views->make('jwtauthorize::roles.index', ['roles' => $roles]);
    }

    /**
     * Show the form to create a role.
     */
    public function create(): View
    {
        return $this->views->make('jwtauthorize::roles.create', [
            'rows' => [['action' => 'allow', 'methods' => '*', 'pathex' => '', 'depth' => 0]],
        ]);
    }

    /**
     * Create a role from the submitted rows.
     */
    public function store(RoleRequest $request): RedirectResponse
    {
        $role = $request->string('name')->value();
        $this->manager->create($role, $this->rows->toPolicies($request->rows()));

        return redirect()->route('jwtauthorize.roles.show', $role)->with('status', "Role [$role] created.");
    }

    /**
     * Show the policies of a role.
     */
    public function show(string $role): View
    {
        return $this->views->make('jwtauthorize::roles.show', ['role' => $role, 'policies' => $this->policies($role)]);
    }

    /**
     * Show the form to edit the policies of a role.
     */
    public function edit(string $role): View
    {
        return $this->views->make('jwtauthorize::roles.edit', [
            'role' => $role,
            'rows' => $this->rows->fromPolicies($this->policies($role)),
        ]);
    }

    /**
     * Replace the policies of a role with the submitted rows.
     */
    public function update(RoleRequest $request, string $role): RedirectResponse
    {
        $this->ensureExists($role);
        $this->manager->update($role, $this->rows->toPolicies($request->rows()));

        return redirect()->route('jwtauthorize.roles.show', $role)->with('status', "Role [$role] updated.");
    }

    /**
     * Move a top-level policy of a role one position up or down.
     */
    public function move(Request $request, string $role, int $index): RedirectResponse
    {
        $this->ensureExists($role);
        $direction = $request->validate(['direction' => ['required', 'in:up,down']])['direction'];

        try {
            $this->manager->move($role, $index, $direction === 'up' ? 'up' : 'down');
        } catch (JwtaRoleException $e) {
            return redirect()->route('jwtauthorize.roles.show', $role)->withErrors(['move' => $e->getMessage()]);
        }

        return redirect()->route('jwtauthorize.roles.show', $role)->with('status', 'Policy moved.');
    }

    /**
     * Delete a role.
     */
    public function destroy(string $role): RedirectResponse
    {
        $this->ensureExists($role);
        $this->manager->delete($role);

        return redirect()->route('jwtauthorize.roles.index')->with('status', "Role [$role] deleted.");
    }

    /**
     * Load the policies of a role, or respond 404 when it does not exist.
     *
     * @return Collection<int, Policy>
     */
    protected function policies(string $role): Collection
    {
        $this->ensureExists($role);

        return $this->manager->get($role);
    }

    /**
     * Respond 404 when the role does not exist.
     */
    protected function ensureExists(string $role): void
    {
        if (! $this->manager->exists($role)) {
            abort(404);
        }
    }
}
