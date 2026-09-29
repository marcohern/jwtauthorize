<?php

declare(strict_types=1);

namespace Marcohern\Jwtauthorize\Exceptions;

use Marcohern\Jwtauthorize\Middleware\Authorize;

/**
 * Thrown when the token's policies do not allow the request (HTTP 403).
 *
 * @see Authorize
 */
class JwtaForbiddenException extends JwtAuthorizeException
{
    protected const int STATUS = 403;
}
