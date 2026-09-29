<?php

declare(strict_types=1);

namespace Marcohern\Jwtauthorize\Tests\Fixtures;

use Illuminate\Foundation\Auth\User as Authenticatable;
use PHPOpenSourceSaver\JWTAuth\Contracts\JWTSubject;

/**
 * User model that can be issued real JWTs in tests.
 */
class JwtUser extends Authenticatable implements JWTSubject
{
    protected $table = 'users';

    protected $guarded = [];

    public function getJWTIdentifier(): mixed
    {
        return $this->getKey();
    }

    /**
     * @return array<string, mixed>
     */
    public function getJWTCustomClaims(): array
    {
        return [];
    }
}
