<?php

declare(strict_types=1);

namespace Marcohern\Jwtauthorize\Exceptions;

/**
 * Thrown when a policy string is malformed or its path regex is invalid.
 *
 * @see \Marcohern\Jwtauthorize\Parser
 */
class JwtaParserException extends JwtAuthorizeException
{
  protected $code = 403;
}