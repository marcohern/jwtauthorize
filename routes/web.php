<?php

declare(strict_types=1);

use Illuminate\Support\Facades\Route;
use Marcohern\Jwtauthorize\Http\Controllers\RoleController;

/*
|--------------------------------------------------------------------------
| Role management UI
|--------------------------------------------------------------------------
|
| Loaded by the service provider only when jwtauthorize.ui.enabled is on,
| inside a group with the configured prefix, middleware and the
| jwtauthorize.manage gate.
|
*/

// "create" is excluded so it cannot be read as a role name.
Route::name('jwtauthorize.roles.')->prefix('roles')->where(['role' => '(?!create$)[A-Za-z0-9_-]+'])->controller(RoleController::class)->group(function () {
    Route::get('/', 'index')->name('index');
    Route::get('/create', 'create')->name('create');
    Route::post('/', 'store')->name('store');
    Route::get('/{role}', 'show')->name('show');
    Route::get('/{role}/edit', 'edit')->name('edit');
    Route::put('/{role}', 'update')->name('update');
    Route::patch('/{role}/policies/{index}/move', 'move')->name('move')->whereNumber('index');
    Route::delete('/{role}', 'destroy')->name('destroy');
});
