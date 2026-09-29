@php
    $depth = (int) ($row['depth'] ?? 0);
    $rowErrors = $i === '__i__' ? [] : array_merge($errors->get("policies.$i"), ...array_values($errors->get("policies.$i.*")));
@endphp
<tr data-depth="{{ $depth }}">
    <td>
        <div class="indent" style="padding-left: {{ $depth * 1.5 }}rem">
            <select data-field="action" name="policies[{{ $i }}][action]" aria-label="Action">
                @foreach (['allow', 'deny'] as $action)
                    <option value="{{ $action }}" @selected(($row['action'] ?? 'allow') === $action)>{{ $action }}</option>
                @endforeach
            </select>
            <input data-field="depth" type="hidden" name="policies[{{ $i }}][depth]" value="{{ $depth }}">
        </div>
    </td>
    <td>
        <input class="mono" data-field="methods" name="policies[{{ $i }}][methods]" value="{{ $row['methods'] ?? '*' }}"
               placeholder="* or GET,POST" aria-label="Methods" size="12">
    </td>
    <td>
        <input class="mono" data-field="pathex" name="policies[{{ $i }}][pathex]" value="{{ $row['pathex'] ?? '' }}"
               placeholder="/\/admin(\/.*)?/" aria-label="Path regex" style="width: 100%" spellcheck="false">
        @foreach ($rowErrors as $error)
            <div class="field-error">{{ $error }}</div>
        @endforeach
    </td>
    <td>
        <div class="actions" style="flex-wrap: nowrap">
            <button class="btn btn-sm" type="button" data-op="up" title="Move up" aria-label="Move up">↑</button>
            <button class="btn btn-sm" type="button" data-op="down" title="Move down" aria-label="Move down">↓</button>
            <button class="btn btn-sm" type="button" data-op="outdent" title="Outdent" aria-label="Outdent">⇤</button>
            <button class="btn btn-sm" type="button" data-op="indent" title="Make it a child of the policy above" aria-label="Indent">⇥</button>
            <button class="btn btn-sm btn-danger" type="button" data-op="remove" title="Remove with its children" aria-label="Remove">✕</button>
        </div>
    </td>
</tr>
