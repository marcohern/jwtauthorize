<?php

declare(strict_types=1);

namespace Marcohern\Jwtauthorize\Exceptions;

/**
 * Thrown when the token's policies do not allow the request (HTTP 403).
 *
 * @see \Marcohern\Jwtauthorize\Middleware\Authorize
 */
class JwtaForbiddenException extends JwtAuthorizeException
{
  protected const STATUS = 403;
}
