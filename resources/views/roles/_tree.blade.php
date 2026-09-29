@foreach ($policies as $index => $policy)
    <tr>
        <td style="padding-left: {{ 0.75 + $depth * 1.5 }}rem">
            @if ($depth > 0)<span class="muted">↳</span>@endif
            <span class="badge badge-{{ $policy->action }}">{{ $policy->action }}</span>
        </td>
        <td><code>{{ $policy->methods }}</code></td>
        <td><code>{{ $policy->pathex }}</code></td>
        <td>
            @if ($depth === 0)
                <div class="actions" style="justify-content: flex-end">
                    @foreach (['up' => '↑', 'down' => '↓'] as $direction => $arrow)
                        <form class="inline" method="POST" action="{{ route('jwtauthorize.roles.move', [$role, $index]) }}">
                            @csrf
                            @method('PATCH')
                            <input type="hidden" name="direction" value="{{ $direction }}">
                            <button class="btn btn-sm" type="submit" title="Move {{ $direction }}" aria-label="Move {{ $direction }}"
                                @disabled(($direction === 'up' && $loop->parent->first) || ($direction === 'down' && $loop->parent->last))>{{ $arrow }}</button>
                        </form>
                    @endforeach
                </div>
            @endif
        </td>
    </tr>
    @include('jwtauthorize::roles._tree', ['policies' => $policy->children, 'depth' => $depth + 1])
@endforeach
