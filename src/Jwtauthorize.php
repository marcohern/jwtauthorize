<?php

declare(strict_types=1);

namespace Marcohern\Jwtauthorize;

use Marcohern\Jwtauthorize\Middleware\Authorize;

class Jwtauthorize
{
    /**
     * Get the middleware that authorizes requests against the JWT `scope` policies.
     *
     * Returns the class name so it can be used directly in route definitions,
     * e.g. `Route::middleware(Jwtauthorize::middleware())`.
     *
     * @return class-string<Authorize>
     */
    public function middleware(): string
    {
        return Authorize::class;
    }
}
