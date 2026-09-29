<div align="center">
    <h1>Jwtauthorize</h1>
</div>

<p align="center">
    <a href="https://packagist.org/packages/marcohern/jwtauthorize"><img src="https://img.shields.io/packagist/v/marcohern/jwtauthorize.svg?style=flat-square" alt="Packagist"></a>
    <a href="https://packagist.org/packages/marcohern/jwtauthorize"><img src="https://img.shields.io/packagist/php-v/marcohern/jwtauthorize.svg?style=flat-square" alt="PHP from Packagist"></a>
    <a href="https://packagist.org/packages/marcohern/jwtauthorize"><img src="https://badge.laravel.cloud/badge/marcohern/jwtauthorize?style=flat" alt="Laravel versions"></a>
    <a href="https://github.com/marcohern/jwtauthorize/actions"><img alt="GitHub Workflow Status (main)" src="https://img.shields.io/github/actions/workflow/status/marcohern/jwtauthorize/tests.yml?branch=main&label=Tests&style=flat-square"></a>
    <a href="https://packagist.org/packages/marcohern/jwtauthorize"><img src="https://img.shields.io/packagist/dt/marcohern/jwtauthorize.svg?style=flat-square" alt="Total Downloads"></a>
</p>



Jwtauthorize authorizes Laravel requests with allow/deny route policies carried in a JWT claim. It is built on [php-open-source-saver/jwt-auth](https://github.com/PHP-Open-Source-Saver/jwt-auth).

## Installation

You can install the package via Composer:

```bash
composer require marcohern/jwtauthorize
```

You may publish the configuration file:

```bash
php artisan vendor:publish --tag="jwtauthorize-config"
```

| Option | Env | Default | Description |
| --- | --- | --- | --- |
| `guard` | `JWTA_GUARD` | default guard | The jwt-auth guard the middleware reads the token from. |
| `claim` | `JWTA_CLAIM` | `scope` | The JWT claim holding the policies. |
| `roles.disk` | `JWTA_ROLES_DISK` | `local` | Filesystem disk holding role files. |
| `roles.path` | `JWTA_ROLES_PATH` | `jwta/roles` | Folder, inside the disk, holding role files. |

## Usage

### Policies

A policy is a string of the form `<action> <methods> <pathex>`:

- `action`: `allow` or `deny`.
- `methods`: `*`, or a comma separated list of HTTP methods with no spaces (`GET,POST`). `GET` also covers `HEAD`.
- `pathex`: a delimited regular expression with no whitespace. It must match the **whole** decoded request path, without the query string. The `m` and `x` modifiers are not allowed.

```text
allow * /.*/                     allow everything
deny POST /\/admin(\/.*)?/       deny POST to /admin and /admin/...
allow GET,HEAD /\/users\/\d+/    allow reading /users/{id}
```

Policies nest. A string key holds a policy, and its value is the list of its more specific children:

```php
[
    'allow * /.*/' => [
        'deny * /\/admin(\/.*)?/' => [
            'allow GET /\/admin\/reports/',
        ],
    ],
]
```

The request is decided like this:

- A matching policy's children refine it. When none of them match, the policy itself decides.
- Among matching siblings, `deny` wins over `allow`.
- Everything else fails closed. No matching policy, an empty or malformed claim, or a policy that fails to evaluate gives a 403. A missing or invalid token gives a 401.

### Protecting routes

Add the `jwta` middleware after the jwt-auth guard:

```php
Route::middleware(['auth:api', 'jwta'])->group(function () {
    Route::get('/posts', [PostController::class, 'index']);
});
```

`Jwtauthorize::middleware()` returns the same middleware class if you prefer a class reference.

### Issuing tokens

Put the policies in the configured claim when you issue the token:

```php
$token = auth('api')
    ->claims(['scope' => ['allow GET /.*/', 'deny * /\/admin(\/.*)?/']])
    ->attempt($credentials);
```

### Roles

Roles are named, reusable lists of policies stored as JSON files. You can manage them with Artisan:

```bash
php artisan jwta:role:create reader "allow GET /.*/"
php artisan jwta:role:create editor --file=editor.json   # nested policies, same shape as above
php artisan jwta:role:update reader "allow GET,POST /.*/"
php artisan jwta:role:list
php artisan jwta:role:show editor
php artisan jwta:role:delete reader
```

Use `PolicyManager::claim()` to put one or more roles' policies in a token:

```php
use Marcohern\Jwtauthorize\PolicyManager;

$token = auth('api')
    ->claims(['scope' => app(PolicyManager::class)->claim('reader', 'editor')])
    ->attempt($credentials);
```

The policies are copied into the token when it is issued, so later role changes apply only to tokens issued after the change.

## Changelog

Please see [CHANGELOG](CHANGELOG.md) for more information on what has changed recently.

## Contributing

Thank you for considering contributing to Jwtauthorize! Please review our [contributing guide](.github/CONTRIBUTING.md) to get started.

## Security Vulnerabilities

Please review [our security policy](.github/SECURITY.md) on how to report security vulnerabilities.

## Credits

- [Marco Hernandez](https://github.com/marcohern)
- [All Contributors](../../contributors)

## License

Jwtauthorize is open-sourced software licensed under the [MIT license](LICENSE.md).
