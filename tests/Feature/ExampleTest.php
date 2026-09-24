<?php

declare(strict_types=1);

use Marcohern\Jwtauthorize\Jwtauthorize;

it('resolves the singleton', function () {
    expect(app(Jwtauthorize::class))->toBeInstanceOf(Jwtauthorize::class);
});

it('returns the same instance from the container', function () {
    expect(app(Jwtauthorize::class))->toBe(app(Jwtauthorize::class));
});

it('merges the package config', function () {
    expect(config('jwtauthorize.placeholder'))->toBe('default');
});

it('loads the package translations', function () {
    expect(trans('jwtauthorize::messages.placeholder'))->toBe('Jwtauthorize placeholder translation.');
});

it('loads the package views', function () {
    expect(view()->exists('jwtauthorize::placeholder'))->toBeTrue();
});

it('registers the artisan command', function () {
    $this->artisan('jwtauthorize:placeholder')
        ->expectsOutputToContain('Jwtauthorize placeholder command executed.')
        ->assertSuccessful();
});
