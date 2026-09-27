<?php

declare(strict_types=1);

namespace Marcohern\Jwtauthorize\Exceptions;

use Exception;

class JwtAuthorizeException extends Exception
{
  protected $code = 401;
}