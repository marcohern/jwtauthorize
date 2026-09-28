<?php

declare(strict_types=1);

namespace Marcohern\Jwtauthorize\Facades;

use Illuminate\Support\Facades\Facade;

/**
 * @method static class-string<\Marcohern\Jwtauthorize\Middleware\Authorize> middleware()
 *
 * @see \Marcohern\Jwtauthorize\Jwtauthorize
 */
class Jwtauthorize extends Facade
{
    protected static function getFacadeAccessor(): string
    {
        return \Marcohern\Jwtauthorize\Jwtauthorize::class;
    }
}
