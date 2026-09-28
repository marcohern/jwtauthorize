<?php

declare(strict_types=1);

namespace Marcohern\Jwtauthorize;

use Illuminate\Support\ServiceProvider;
use Marcohern\Jwtauthorize\Console\Commands\RoleCreateCommand;
use Marcohern\Jwtauthorize\Console\Commands\RoleDeleteCommand;
use Marcohern\Jwtauthorize\Console\Commands\RoleListCommand;
use Marcohern\Jwtauthorize\Console\Commands\RoleShowCommand;
use Marcohern\Jwtauthorize\Console\Commands\RoleUpdateCommand;

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
        $this->loadRoutesFrom(__DIR__.'/../routes/jwtauthorize.php');

        $this->loadViewsFrom(__DIR__.'/../resources/views', 'jwtauthorize');

        $this->loadTranslationsFrom(__DIR__.'/../lang', 'jwtauthorize');

        if (! $this->app->runningInConsole()) {
            return;
        }

        $this->publishes([
            __DIR__.'/../config/jwtauthorize.php' => config_path('jwtauthorize.php'),
        ], ['jwtauthorize', 'jwtauthorize-config']);

        $this->publishes([
            __DIR__.'/../resources/views' => resource_path('views/vendor/jwtauthorize'),
        ], ['jwtauthorize', 'jwtauthorize-views']);

        $this->publishes([
            __DIR__.'/../lang' => $this->app->langPath('vendor/jwtauthorize'),
        ], ['jwtauthorize', 'jwtauthorize-lang']);

        $this->publishes([
            __DIR__.'/../public' => public_path('vendor/jwtauthorize'),
        ], ['jwtauthorize', 'jwtauthorize-assets']);

        $this->publishesMigrations([
            __DIR__.'/../database/migrations' => database_path('migrations'),
        ], ['jwtauthorize', 'jwtauthorize-migrations']);

        $this->commands([
            RoleCreateCommand::class,
            RoleUpdateCommand::class,
            RoleDeleteCommand::class,
            RoleListCommand::class,
            RoleShowCommand::class,
        ]);
    }
}
