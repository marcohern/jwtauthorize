<?php

declare(strict_types=1);

return [

    'placeholder' => 'default',

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

];
