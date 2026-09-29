# Release Notes

## [Unreleased](https://github.com/marcohern/jwtauthorize/compare/0.5.0...main)

## [0.5.0](https://github.com/marcohern/jwtauthorize/compare/0.4.0...0.5.0) - 2026-09-29

### Added

- Sort policies by specificity in the role editor: ⇅ on a row sorts its direct children, and **Sort top level** sorts the top-level policies, longest path regex first. Only that one level is sorted: children move with their parent, and equal lengths keep their order.

## [0.4.0](https://github.com/marcohern/jwtauthorize/compare/0.3.0...0.4.0) - 2026-09-29

### Added

- Role tester: the **Test policies** page (`jwtauthorize.test`, linked from every role) and the `jwta:role:test {role} {method} {path}` command. They show whether a role allows a request, the deciding policy and its parents, and how every policy matched. The command exits 0 when allowed and 1 when denied.
- `PolicyEvaluator`, the decision shared by the middleware and the tester, returning an `Evaluation` trace.
- `Parser::methods()`. `Parser::methodMatches()` and `Parser::uriMatches()` are now public.

### Changed

- The `Authorize` middleware takes a `PolicyEvaluator` instead of a `Parser`. The decisions are unchanged.

## [0.3.0](https://github.com/marcohern/jwtauthorize/compare/0.2.0...0.3.0) - 2026-09-28

### Added

- Role management pages to list, view, create, edit, reorder and delete roles (`RoleController`, `jwtauthorize::roles.*` views). Off by default: enable with `jwtauthorize.ui.enabled` (`JWTA_UI`). The pages run behind `jwtauthorize.ui.middleware` and the `jwtauthorize.manage` gate, which only allows the local environment unless the app defines it.
- `PolicyManager::move()` to move a top-level policy up or down.
- `jwtauthorize-views` publish tag.

### Changed

- `jwta:role:list` no longer extends the internal `RoleCommand` base class.

## [0.2.0](https://github.com/marcohern/jwtauthorize/compare/0.1.1...0.2.0) - 2026-09-28

### Added

- `PolicyManager::claim(...$roles)` returns the policies of one or more roles in the shape carried by the JWT claim.
- `Policy::toArray()`, the plain-array shape used by role files and JWT claims.
- `PolicyBuilder` accepts associative-array policies, which is how jwt-auth decodes a claim built with `claim()`.
- `Parser::validate()`; policies built from arrays, objects and role files are now validated like policy strings.
- `jwta` middleware alias.
- `jwtauthorize.roles.disk` and `jwtauthorize.roles.path` config options for role storage.

### Changed

- `HEAD` requests are covered by `GET` policies, matching Laravel's routing.
- Pathex modifiers `m` and `x` are rejected; they could weaken the full-path anchor.
- `PolicyBuilder` throws `JwtaParserException` instead of `BadRequestHttpException` for unsupported definitions.
- `PolicyBuilder::from()` appends `$children` to a `Policy` instead of ignoring them.
- Requires `laravel/framework` instead of only `illuminate/support`.

### Removed

- Placeholder skeleton resources: migration, view, translation, public assets and routes, and their publish tags (`jwtauthorize-migrations`, `jwtauthorize-views`, `jwtauthorize-lang`, `jwtauthorize-assets`).

## [0.1.1](https://github.com/marcohern/jwtauthorize/compare/0.1.0...0.1.1) - 2026-09-28

- `jwta:role:create`, `jwta:role:update`, `jwta:role:delete`, `jwta:role:list` and `jwta:role:show` commands.
- `PolicyManager` for storing roles.

## [0.1.0](https://github.com/marcohern/jwtauthorize/releases/tag/0.1.0) - 2026-09-25

Initial pre-release.
