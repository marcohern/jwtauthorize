<?php

declare(strict_types=1);

namespace Marcohern\Jwtauthorize;

use Illuminate\Routing\Router;
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

        if (! $this->app->runningInConsole()) {
            return;
        }

        $this->publishes([
            __DIR__.'/../config/jwtauthorize.php' => config_path('jwtauthorize.php'),
        ], ['jwtauthorize', 'jwtauthorize-config']);

        $this->commands([
            RoleCreateCommand::class,
            RoleUpdateCommand::class,
            RoleDeleteCommand::class,
            RoleListCommand::class,
            RoleShowCommand::class,
        ]);
    }
}
