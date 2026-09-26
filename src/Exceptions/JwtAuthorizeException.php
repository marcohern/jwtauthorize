<?php

declare(strict_types=1);

namespace Marcohern\Jwtauthorize\Exceptions\JwtaUnauthorizedException;
use \Exceptions;

class JwtAuthorizeException extends Exceptions
{
  protected $code = 401;
}