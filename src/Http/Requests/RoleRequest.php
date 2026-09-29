<?php

declare(strict_types=1);

namespace Marcohern\Jwtauthorize\Http\Requests;

use Closure;
use Illuminate\Foundation\Http\FormRequest;
use Illuminate\Validation\Validator;
use Marcohern\Jwtauthorize\Exceptions\JwtaParserException;
use Marcohern\Jwtauthorize\Http\PolicyRows;
use Marcohern\Jwtauthorize\Parser;
use Marcohern\Jwtauthorize\PolicyManager;

/**
 * Validates the role form: the role name (on create) and the policy rows.
 *
 * Rows follow {@see PolicyRows}. Each row is
 * checked with {@see Parser::validate()}, and errors are keyed by row
 * (`policies.{i}`) so the form can show them next to the policy.
 */
class RoleRequest extends FormRequest
{
    /**
     * Access is checked by the route middleware (the `jwtauthorize.manage` gate).
     */
    public function authorize(): bool
    {
        return true;
    }

    /**
     * Respond 404 before validating when the edited role does not exist.
     */
    protected function prepareForValidation(): void
    {
        $role = $this->route('role');

        if (is_string($role) && ! $this->container->make(PolicyManager::class)->exists($role)) {
            abort(404);
        }
    }

    /**
     * @return array<string, mixed>
     */
    public function rules(): array
    {
        $rules = [
            'policies' => ['required', 'array', 'list', 'min:1'],
            'policies.*' => ['required', 'array'],
            'policies.*.action' => ['required', 'in:allow,deny'],
            'policies.*.methods' => ['required', 'string', 'max:255'],
            'policies.*.pathex' => ['required', 'string', 'max:1000'],
            'policies.*.depth' => ['required', 'integer', 'min:0', 'max:32'],
        ];

        if ($this->isCreating()) {
            $rules['name'] = ['required', 'string', 'max:100', 'regex:/^[A-Za-z0-9_-]+$/', 'not_in:create'];
        }

        return $rules;
    }

    /**
     * @return array<string, string>
     */
    public function attributes(): array
    {
        return [
            'policies.*.action' => 'action',
            'policies.*.methods' => 'methods',
            'policies.*.pathex' => 'path regex',
            'policies.*.depth' => 'nesting',
        ];
    }

    /**
     * Checks that need the rules above to pass first: name uniqueness, nesting and policy grammar.
     *
     * @return array<int, Closure(Validator): void>
     */
    public function after(PolicyManager $manager, Parser $parser): array
    {
        return [
            function (Validator $validator) use ($manager, $parser): void {
                if ($validator->errors()->isNotEmpty()) {
                    return;
                }

                if ($this->isCreating() && $manager->exists($this->string('name')->value())) {
                    $validator->errors()->add('name', 'A role with this name already exists.');
                }

                $previousDepth = -1;
                foreach ($this->rows() as $i => $row) {
                    if ($row['depth'] > $previousDepth + 1) {
                        $validator->errors()->add("policies.$i", 'A policy can only be one level deeper than the policy above it.');
                    }
                    $previousDepth = $row['depth'];

                    if (preg_match('/\s/', $row['pathex']) === 1) {
                        $validator->errors()->add("policies.$i", 'The path regex cannot contain whitespace.');

                        continue;
                    }

                    try {
                        $parser->validate($row['action'], $row['methods'], $row['pathex']);
                    } catch (JwtaParserException $e) {
                        $message = $e->getMessage() === 'Policy invalid.'
                            ? 'Methods must be * or a comma separated list of HTTP methods, e.g. GET,POST.'
                            : $e->getMessage();
                        $validator->errors()->add("policies.$i", $message);
                    }
                }
            },
        ];
    }

    /**
     * Get the submitted policy rows, typed.
     *
     * @return list<array{action: string, methods: string, pathex: string, depth: int}>
     */
    public function rows(): array
    {
        $rows = [];
        foreach ((array) $this->input('policies', []) as $row) {
            $row = is_array($row) ? $row : [];
            $rows[] = [
                'action' => $this->text($row['action'] ?? ''),
                'methods' => strtoupper((string) preg_replace('/\s+/', '', $this->text($row['methods'] ?? ''))),
                'pathex' => $this->text($row['pathex'] ?? ''),
                'depth' => (int) (is_numeric($row['depth'] ?? null) ? $row['depth'] : 0),
            ];
        }

        return $rows;
    }

    /**
     * Whether the request creates a role (no `{role}` route parameter).
     */
    protected function isCreating(): bool
    {
        return $this->route('role') === null;
    }

    /**
     * Convert a submitted scalar to a trimmed string.
     */
    private function text(mixed $value): string
    {
        return is_scalar($value) ? trim((string) $value) : '';
    }
}
