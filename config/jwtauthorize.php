<?php

declare(strict_types=1);

return [

    /*
    |--------------------------------------------------------------------------
    | Guard
    |--------------------------------------------------------------------------
    |
    | The JWT auth guard the Authorize middleware reads the token from.
    | Null uses the application's default guard.
    |
    */

    'guard' => env('JWTA_GUARD'),

    /*
    |--------------------------------------------------------------------------
    | Claim
    |--------------------------------------------------------------------------
    |
    | The JWT claim holding the policy list. Consider a dedicated name (e.g.
    | "jwta") so it does not clash with the standard OAuth "scope" string.
    |
    */

    'claim' => env('JWTA_CLAIM', 'scope'),

    /*
    |--------------------------------------------------------------------------
    | Roles
    |--------------------------------------------------------------------------
    |
    | Where the jwta:role:* commands and the PolicyManager store role files:
    | the filesystem disk, and the folder inside it.
    |
    */

    'roles' => [
        'disk' => env('JWTA_ROLES_DISK', 'local'),
        'path' => env('JWTA_ROLES_PATH', 'jwta/roles'),
    ],

    /*
    |--------------------------------------------------------------------------
    | Role management UI
    |--------------------------------------------------------------------------
    |
    | Web pages to list, view, create, edit, reorder and delete roles, served
    | under the prefix (e.g. /jwta/roles). They are only registered when
    | enabled. Besides the middleware, every page requires the
    | "jwtauthorize.manage" gate, which only allows the local environment
    | unless the application defines it.
    |
    */

    'ui' => [
        'enabled' => (bool) env('JWTA_UI', false),
        'prefix' => env('JWTA_UI_PREFIX', 'jwta'),
        'middleware' => ['web', 'auth'],
    ],

];
