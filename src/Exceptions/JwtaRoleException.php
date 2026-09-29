<?php

declare(strict_types=1);

namespace Marcohern\Jwtauthorize\Exceptions;

use Marcohern\Jwtauthorize\PolicyManager;

/**
 * Thrown when a role name is invalid, or a role is missing or already exists.
 *
 * @see PolicyManager
 */
class JwtaRoleException extends JwtAuthorizeException
{
    protected const int STATUS = 422;
}
