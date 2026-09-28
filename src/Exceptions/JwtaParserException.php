<?php

declare(strict_types=1);

namespace Marcohern\Jwtauthorize\Exceptions;

/**
 * Thrown when a policy string is malformed or its path regex is invalid or fails to evaluate.
 *
 * @see \Marcohern\Jwtauthorize\Parser
 */
class JwtaParserException extends JwtAuthorizeException
{
  protected const STATUS = 422;
}
