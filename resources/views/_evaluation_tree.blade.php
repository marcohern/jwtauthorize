@foreach ($nodes as $node)
    @php
        $classes = array_filter([
            $node->onDecisionPath ? 'on-path' : null,
            $node->decides ? 'decides' : null,
            $node->status === 'not_evaluated' ? 'not-evaluated' : null,
        ]);
        $mark = fn (?bool $value): string => match ($value) {
            true => '<span class="yes" title="Matches">✓</span>',
            false => '<span class="no" title="Does not match">✗</span>',
            null => '<span class="muted" title="Not checked">–</span>',
        };
    @endphp
    <tr class="{{ implode(' ', $classes) }}">
        <td style="padding-left: {{ 0.75 + $depth * 1.5 }}rem">
            @if ($depth > 0)<span class="muted">↳</span>@endif
            <span class="badge badge-{{ $node->policy->action }}">{{ $node->policy->action }}</span>
        </td>
        <td><code>{{ $node->policy->methods }}</code></td>
        <td><code>{{ $node->policy->pathex }}</code></td>
        <td class="check">{!! $mark($node->methodMatched) !!}</td>
        <td class="check">{!! $mark($node->pathMatched) !!}</td>
        <td>
            @if ($node->decides)
                <span class="tag">decides</span>
            @elseif ($node->status === 'matched')
                matched
            @elseif ($node->status === 'unmatched')
                <span class="muted">no match</span>
            @elseif ($parentMatched)
                <span class="muted" title="A deny above already decided the request.">not reached</span>
            @else
                <span class="muted" title="Its parent did not match, so it was not checked.">not checked</span>
            @endif
        </td>
    </tr>
    @include('jwtauthorize::_evaluation_tree', ['nodes' => $node->children, 'depth' => $depth + 1, 'parentMatched' => $node->status === 'matched'])
@endforeach
