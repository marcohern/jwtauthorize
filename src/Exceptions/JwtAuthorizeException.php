<?php

declare(strict_types=1);

namespace Marcohern\Jwtauthorize\Exceptions;

use Exception;

/**
 * Base exception for every error raised by the jwtauthorize package.
 *
 * Catch this type to handle any package error in one place.
 */
class JwtAuthorizeException extends Exception
{
  protected $code = 401;
}