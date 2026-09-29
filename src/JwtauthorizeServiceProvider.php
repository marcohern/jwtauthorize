<?php

declare(strict_types=1);

namespace Marcohern\Jwtauthorize;

use Illuminate\Routing\Router;
use Illuminate\Support\Facades\Gate;
use Illuminate\Support\Facades\Route;
use Illuminate\Support\ServiceProvider;
use Marcohern\Jwtauthorize\Console\Commands\RoleCreateCommand;
use Marcohern\Jwtauthorize\Console\Commands\RoleDeleteCommand;
use Marcohern\Jwtauthorize\Console\Commands\RoleListCommand;
use Marcohern\Jwtauthorize\Console\Commands\RoleShowCommand;
use Marcohern\Jwtauthorize\Console\Commands\RoleUpdateCommand;
use Marcohern\Jwtauthorize\Middleware\Authorize;

class JwtauthorizeServiceProvider extends ServiceProvider
{
    /**
     * Register any application services.
     */
    public function register(): void
    {
        $this->mergeConfigFrom(__DIR__.'/../config/jwtauthorize.php', 'jwtauthorize');

        $this->app->singleton(Jwtauthorize::class);
        $this->app->singleton(PolicyManager::class);
    }

    /**
     * Bootstrap any application services.
     */
    public function boot(): void
    {
        $this->app->make(Router::class)->aliasMiddleware('jwta', Authorize::class);

        $this->loadViewsFrom(__DIR__.'/../resources/views', 'jwtauthorize');
        $this->registerUi();

        if (! $this->app->runningInConsole()) {
            return;
        }

        $this->publishes([
            __DIR__.'/../config/jwtauthorize.php' => config_path('jwtauthorize.php'),
        ], ['jwtauthorize', 'jwtauthorize-config']);

        $this->publishes([
            __DIR__.'/../resources/views' => resource_path('views/vendor/jwtauthorize'),
        ], ['jwtauthorize', 'jwtauthorize-views']);

        $this->commands([
            RoleCreateCommand::class,
            RoleUpdateCommand::class,
            RoleDeleteCommand::class,
            RoleListCommand::class,
            RoleShowCommand::class,
        ]);
    }

    /**
     * Register the role management pages when `jwtauthorize.ui.enabled` is on.
     *
     * Every page requires the `jwtauthorize.manage` gate. Unless the
     * application defines it, the gate only allows the local environment.
     */
    protected function registerUi(): void
    {
        if (! Gate::has('jwtauthorize.manage')) {
            Gate::define('jwtauthorize.manage', fn (mixed $user = null): bool => $this->app->environment('local'));
        }

        if (! config('jwtauthorize.ui.enabled') || $this->app->routesAreCached()) {
            return;
        }

        Route::group([
            'prefix' => config('jwtauthorize.ui.prefix', 'jwta'),
            'middleware' => [...(array) config('jwtauthorize.ui.middleware', ['web', 'auth']), 'can:jwtauthorize.manage'],
        ], function (): void {
            $this->loadRoutesFrom(__DIR__.'/../routes/web.php');
        });
    }
}
