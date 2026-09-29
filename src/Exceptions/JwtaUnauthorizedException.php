<?php

declare(strict_types=1);

namespace Marcohern\Jwtauthorize\Exceptions;

/**
 * Thrown when the request carries no valid token (HTTP 401).
 */
class JwtaUnauthorizedException extends JwtAuthorizeException
{
    protected const int STATUS = 401;

    protected const array HEADERS = ['WWW-Authenticate' => 'Bearer'];
}
