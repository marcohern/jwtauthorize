---
name: jwtauthorize-development
description: >
  Configure and apply the Jwtauthorize package in Laravel applications: protect routes with
  allow/deny policies carried in a JWT claim, manage roles, and issue tokens with policies.
license: MIT
metadata:
  author: Marco Hernandez
---

# Jwtauthorize

Use this skill when a Laravel application needs to authorize requests with `marcohern/jwtauthorize`.

## Primary Goal

- apply the `marcohern/jwtauthorize` package's public API in the smallest correct way

## Workflow

### 1. Inspect the Laravel app context

- confirm the app uses `php-open-source-saver/jwt-auth` with a `jwt` guard (usually `api`)
- set `jwtauthorize.guard` / `JWTA_GUARD` when that guard is not the default one
- find where tokens are issued (login controller) and which routes need authorization

### 2. Apply the package's public API

- Protect routes with the `jwta` middleware alias, after the auth guard: `Route::middleware(['auth:api', 'jwta'])`.
- Put policies in the `scope` claim (or `jwtauthorize.claim`) when issuing the token:
  `auth('api')->claims(['scope' => [...]])->attempt($credentials)`.
- For reusable policy sets, create roles with `php artisan jwta:role:create <role> "<policy>" ...` or `--file=<json>`,
  then issue tokens with `app(\Marcohern\Jwtauthorize\PolicyManager::class)->claim('role-a', 'role-b')`.
- For a browser UI to manage roles, set `JWTA_UI=true`, make sure `jwtauthorize.ui.middleware` has a session login
  (default `['web', 'auth']`), and define the `jwtauthorize.manage` gate for the users allowed to manage roles.
- To check what a role allows, run `php artisan jwta:role:test <role> <METHOD> <path>` (exit 0 allowed, 1 denied),
  or open the Test policies page (`/jwta/test`). Both show the deciding policy and its parents.

### Policy grammar

- `<action> <methods> <pathex>`: `allow|deny`, `*` or `GET,POST` (no spaces), and a delimited regex with no whitespace.
- The pathex must match the whole decoded path (no query string). The `m` and `x` modifiers are rejected.
- Nest with string keys: `['allow * /.*/' => ['deny * /\/admin(\/.*)?/']]`. Children refine their parent, and among matching siblings `deny` wins.
- Anything unmatched or malformed is a 403. A missing token is a 401.

## Rules, References, and Templates

Read before executing:

- the package README, "Usage" section

## Examples

- Allow read-only access except for admin routes:
  `['allow GET /.*/', 'deny * /\/admin(\/.*)?/']`
- Deny all of `/orgs` but allow its reports:
  `['deny * /\/orgs(\/.*)?/' => ['allow GET /\/orgs\/reports(\/.*)?/']]`

## Anti-patterns

- do not put policies in the OAuth-style `scope` string format (`"read write"`); the claim must be a list
- do not rely on the query string or a path prefix; policies match the whole path
- do not expect role edits to affect tokens that were already issued; the policies are copied into the token
