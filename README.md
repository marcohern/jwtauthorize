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



## Installation

You can install the package via Composer:

```bash
composer require marcohern/jwtauthorize
```

You may publish all of the package's resources at once:

```bash
php artisan vendor:publish --tag="jwtauthorize"
```

Or, you may publish each resource individually:

### Publishing the Configuration File

```bash
php artisan vendor:publish --tag="jwtauthorize-config"
```

### Publishing and Running the Migrations

```bash
php artisan vendor:publish --tag="jwtauthorize-migrations"
php artisan migrate
```

### Publishing the Views

```bash
php artisan vendor:publish --tag="jwtauthorize-views"
```

### Publishing the Translations

```bash
php artisan vendor:publish --tag="jwtauthorize-lang"
```

### Publishing the Public Assets

```bash
php artisan vendor:publish --tag="jwtauthorize-assets"
```

## Usage

<!-- Add a basic usage example here. -->

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
