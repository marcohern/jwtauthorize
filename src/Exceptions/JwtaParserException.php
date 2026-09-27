<?php

declare(strict_types=1);

namespace Marcohern\Jwtauthorize\Exceptions;

class JwtaParserException extends JwtAuthorizeException
{
  protected $code = 403;
}