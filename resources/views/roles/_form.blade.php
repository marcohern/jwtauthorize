@php
    $rows = array_values((array) old('policies', $rows));
@endphp
<form id="jwta-role-form" method="POST" action="{{ $action }}">
    @csrf
    @isset($role)
        @method('PUT')
    @endisset

    <div class="field">
        <label for="jwta-name">Name</label>
        @isset($role)
            <input id="jwta-name" class="mono" value="{{ $role }}" readonly>
        @else
            <input id="jwta-name" class="mono" name="name" value="{{ old('name') }}" required pattern="[A-Za-z0-9_\-]+"
                   maxlength="100" autocomplete="off" autofocus>
            <p class="hint">Letters, digits, <code>-</code> and <code>_</code>.</p>
            @error('name')
                <div class="field-error">{{ $message }}</div>
            @enderror
        @endisset
    </div>

    <div class="card">
        <table>
            <thead>
                <tr>
                    <th>Action</th>
                    <th>Methods</th>
                    <th style="width: 100%">Path regex</th>
                    <th><span class="sr-only">Arrange</span></th>
                </tr>
            </thead>
            <tbody id="jwta-rows">
                @foreach ($rows as $i => $row)
                    @include('jwtauthorize::roles._row', ['i' => $i, 'row' => (array) $row])
                @endforeach
            </tbody>
        </table>
    </div>
    <p class="hint">
        A policy is <code>action methods pathex</code>. The regex must match the whole path, e.g.
        <code>/\/admin(\/.*)?/</code> for <code>/admin</code> and everything under it.
        Indent a policy to make it a child that refines the policy above it.
        <code>⇅</code> sorts one level by specificity: longer path regexes first; children move with their parent.
    </p>

    <div class="bar" style="margin-top: 1rem">
        <div class="actions">
            <button class="btn" type="button" data-op="add">+ Add policy</button>
            <button class="btn" type="button" data-op="sort-root" title="Sort top-level policies, most specific (longest path regex) first">⇅ Sort top level</button>
        </div>
        <div class="actions">
            <a class="btn" href="{{ isset($role) ? route('jwtauthorize.roles.show', $role) : route('jwtauthorize.roles.index') }}">Cancel</a>
            <button class="btn btn-primary" type="submit">Save</button>
        </div>
    </div>
</form>

<template id="jwta-row-template">
    @include('jwtauthorize::roles._row', ['i' => '__i__', 'row' => ['action' => 'allow', 'methods' => '*', 'pathex' => '', 'depth' => 0]])
</template>

@push('scripts')
<script>
(() => {
    const form = document.getElementById('jwta-role-form');
    const body = document.getElementById('jwta-rows');
    const template = document.getElementById('jwta-row-template');

    const rows = () => [...body.children];
    const depth = (row) => Number(row.dataset.depth);

    /** The row followed by all of its descendants. */
    const block = (row) => {
        const all = rows();
        const found = [row];
        for (let i = all.indexOf(row) + 1; i < all.length && depth(all[i]) > depth(row); i++) {
            found.push(all[i]);
        }
        return found;
    };

    const previousSibling = (row) => {
        let other = row.previousElementSibling;
        while (other && depth(other) > depth(row)) other = other.previousElementSibling;
        return other && depth(other) === depth(row) ? other : null;
    };

    const nextSibling = (row) => {
        const other = block(row).at(-1).nextElementSibling;
        return other && depth(other) === depth(row) ? other : null;
    };

    /** The direct children of a row. */
    const children = (row) => block(row).slice(1).filter((item) => depth(item) === depth(row) + 1);

    const topLevel = () => rows().filter((row) => depth(row) === 0);

    const pathLength = (row) => row.querySelector('[data-field="pathex"]').value.length;

    /** Reorder adjacent siblings, longest path regex first, keeping each one's descendants under it. */
    const sortSiblings = (siblings) => {
        if (siblings.length < 2) return;

        const anchor = siblings[0].previousElementSibling;
        const blocks = siblings.map((sibling) => ({ length: pathLength(sibling), rows: block(sibling) }));
        const sorted = blocks.sort((a, b) => b.length - a.length).flatMap((item) => item.rows);

        if (anchor) anchor.after(...sorted);
        else body.prepend(...sorted);
    };

    const canIndent = (row) => {
        const above = row.previousElementSibling;
        return above !== null && depth(above) >= depth(row);
    };

    const setDepth = (row, value) => {
        row.dataset.depth = value;
        row.querySelector('[data-field="depth"]').value = value;
        row.querySelector('.indent').style.paddingLeft = (value * 1.5) + 'rem';
    };

    const addRow = () => {
        body.append(template.content.firstElementChild.cloneNode(true));
    };

    /** Renumber field names in row order and enable only the moves that are possible. */
    const refresh = () => {
        rows().forEach((row, index) => {
            row.querySelectorAll('[data-field]').forEach((field) => {
                field.name = `policies[${index}][${field.dataset.field}]`;
            });
            row.querySelector('[data-op="up"]').disabled = !previousSibling(row);
            row.querySelector('[data-op="down"]').disabled = !nextSibling(row);
            row.querySelector('[data-op="outdent"]').disabled = depth(row) === 0;
            row.querySelector('[data-op="indent"]').disabled = !canIndent(row);
            row.querySelector('[data-op="sort"]').disabled = children(row).length < 2;
        });
        form.querySelector('[data-op="sort-root"]').disabled = topLevel().length < 2;
    };

    const operations = {
        up(row) {
            const other = previousSibling(row);
            if (other) other.before(...block(row));
        },
        down(row) {
            const other = nextSibling(row);
            if (other) block(other).at(-1).after(...block(row));
        },
        indent(row) {
            if (canIndent(row)) block(row).forEach((item) => setDepth(item, depth(item) + 1));
        },
        outdent(row) {
            if (depth(row) > 0) block(row).forEach((item) => setDepth(item, depth(item) - 1));
        },
        remove(row) {
            block(row).forEach((item) => item.remove());
            if (rows().length === 0) addRow();
        },
        sort(row) {
            sortSiblings(children(row));
        },
    };

    form.addEventListener('click', (event) => {
        const button = event.target.closest('[data-op]');
        if (!button) return;

        const operation = button.dataset.op;
        if (operation === 'add') {
            addRow();
            rows().at(-1).querySelector('[data-field="pathex"]').focus();
        } else if (operation === 'sort-root') {
            sortSiblings(topLevel());
        } else {
            operations[operation](button.closest('tr'));
        }
        refresh();
    });

    form.addEventListener('submit', refresh);
    refresh();
})();
</script>
@endpush
