<?php

declare(strict_types=1);

namespace Marcohern\Jwtauthorize\Exceptions;
use \Exceptions;

class JwtaUnauthorizedException extends JwtAuthorizeException
{
  protected $code = 400;
}