<?php

declare(strict_types=1);

namespace Jwtauthorize\Jwtauthorize\Facades;

use Illuminate\Support\Facades\Facade;

/**
 * @see \Jwtauthorize\Jwtauthorize\Jwtauthorize
 */
class Jwtauthorize extends Facade
{
    protected static function getFacadeAccessor(): string
    {
        return \Jwtauthorize\Jwtauthorize\Jwtauthorize::class;
    }
}
