<?php

declare(strict_types=1);

namespace Marcohern\Jwtauthorize\Exceptions;

/**
 * Thrown when a role name is invalid, or a role is missing or already exists.
 *
 * @see \Marcohern\Jwtauthorize\PolicyManager
 */
class JwtaRoleException extends JwtAuthorizeException
{
  protected const STATUS = 422;
}
