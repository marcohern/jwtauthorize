<?php

declare(strict_types=1);

namespace Marcohern\Jwtauthorize\Exceptions;
/**
 * Thrown when the request is not allowed by the token's policies.
 */
class JwtaUnauthorizedException extends JwtAuthorizeException
{
  protected $code = 400;
}