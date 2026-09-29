<?php

declare(strict_types=1);

namespace Marcohern\Jwtauthorize\Exceptions;

use Marcohern\Jwtauthorize\Parser;

/**
 * Thrown when a policy string is malformed or its path regex is invalid or fails to evaluate.
 *
 * @see Parser
 */
class JwtaParserException extends JwtAuthorizeException
{
    protected const int STATUS = 422;
}
