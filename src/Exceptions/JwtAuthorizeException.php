<?php

declare(strict_types=1);

namespace Marcohern\Jwtauthorize\Exceptions;

use Symfony\Component\HttpKernel\Exception\HttpException;
use Throwable;

/**
 * Base exception for every error raised by the jwtauthorize package.
 *
 * Catch this type to handle any package error in one place. Being an HTTP
 * exception, Laravel renders it with {@see JwtAuthorizeException::STATUS}
 * instead of a 500, and does not report it to the logs.
 */
class JwtAuthorizeException extends HttpException
{
  /**
   * HTTP status code the exception renders with.
   */
  protected const STATUS = 403;

  /**
   * HTTP headers the exception renders with.
   */
  protected const HEADERS = [];

  /**
   * @param  string  $message  Error message.
   * @param  Throwable|null  $previous  The exception that caused this one.
   */
  public function __construct(string $message = '', ?Throwable $previous = null)
  {
    parent::__construct(static::STATUS, $message, $previous, static::HEADERS);
  }
}
