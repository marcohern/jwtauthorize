@extends('jwtauthorize::layout')

@section('title', 'Test policies')

@push('head')
    <style>
        .test-form { display: flex; flex-wrap: wrap; gap: .75rem; align-items: flex-end; padding: 1rem; }
        .test-form .grow { flex: 1 1 18rem; }
        .test-form .grow input { width: 100%; }
        .verdict { display: flex; gap: .9rem; align-items: flex-start; padding: .9rem 1.1rem; border-radius: .5rem; margin: 1.25rem 0 1rem; }
        .verdict strong { font-size: 1.25rem; line-height: 1.2; }
        .verdict p { margin: .15rem 0 0; }
        .verdict-allow { background: var(--allow-bg); color: var(--allow); }
        .verdict-deny { background: var(--deny-bg); color: var(--deny); }
        .chain { margin: .35rem 0 0; padding-left: 1.1rem; }
        .chain code { color: var(--text); }
        tr.on-path td { background: var(--notice-bg); }
        tr.decides td { font-weight: 600; }
        tr.not-evaluated td { opacity: .5; }
        .check { font-weight: 600; text-align: center; width: 4.5rem; }
        .yes { color: var(--allow); }
        .no { color: var(--deny); }
        .tag { display: inline-block; padding: .05rem .5rem; border-radius: 999px; font-size: .75rem; background: var(--accent); color: var(--accent-text); }
    </style>
@endpush

@section('content')
    <div class="bar">
        <h1>Test policies</h1>
    </div>

    @if ($roles->isEmpty())
        <div class="card"><p class="empty">No roles yet. <a href="{{ route('jwtauthorize.roles.create') }}">Create one</a> to test it.</p></div>
    @else
        <form class="card test-form" method="GET" action="{{ route('jwtauthorize.test') }}">
            <div>
                <label for="jwta-role">Role</label>
                <select id="jwta-role" name="role" required>
                    @foreach ($roles as $role)
                        <option value="{{ $role }}" @selected(request('role') === $role)>{{ $role }}</option>
                    @endforeach
                </select>
            </div>
            <div>
                <label for="jwta-method">Method</label>
                <select id="jwta-method" name="method" required>
                    @foreach ($methods as $method)
                        <option value="{{ $method }}" @selected(request('method', 'GET') === $method)>{{ $method }}</option>
                    @endforeach
                </select>
            </div>
            <div class="grow">
                <label for="jwta-path">Path</label>
                <input id="jwta-path" class="mono" name="path" value="{{ request('path') }}" placeholder="/api/users/1 or a full URL"
                       required maxlength="2000" spellcheck="false" autocomplete="off" @if (request()->filled('role')) autofocus @endif>
            </div>
            <button class="btn btn-primary" type="submit">Test</button>
        </form>
    @endif

    @if ($failure !== null)
        <div class="verdict verdict-deny" role="status">
            <strong>Denied</strong>
            <div>
                <p>A policy failed to evaluate, so the middleware fails closed and denies the request.</p>
                <p><code>{{ $failure }}</code></p>
            </div>
        </div>
    @elseif ($evaluation !== null)
        @php
            $decider = $evaluation->decidingNode();
            $ancestors = array_slice($evaluation->chain, 0, -1);
        @endphp
        <div class="verdict {{ $evaluation->allowed() ? 'verdict-allow' : 'verdict-deny' }}" role="status">
            <strong>{{ $evaluation->allowed() ? 'Allowed' : 'Denied' }}</strong>
            <div>
                <p>
                    <code>{{ $evaluation->method }} {{ $evaluation->path }}</code> for role <code>{{ $input['role'] }}</code>
                    @if ($evaluation->path !== $input['path'])
                        <span class="muted">(normalized from <code>{{ $input['path'] }}</code>)</span>
                    @endif
                </p>
                @if ($decider === null)
                    <p>No policy matched, and a request no policy matches is denied.</p>
                @else
                    <p>Decided by <code>{{ $decider->policy->action }} {{ $decider->policy->methods }} {{ $decider->policy->pathex }}</code></p>
                    @if ($ancestors !== [])
                        <ol class="chain" aria-label="Parent policies">
                            @foreach (array_reverse($ancestors) as $ancestor)
                                <li>under <code>{{ $ancestor->policy->action }} {{ $ancestor->policy->methods }} {{ $ancestor->policy->pathex }}</code></li>
                            @endforeach
                        </ol>
                    @endif
                @endif
            </div>
        </div>

        <div class="card">
            <table>
                <thead>
                    <tr>
                        <th>Action</th>
                        <th>Methods</th>
                        <th>Path regex</th>
                        <th class="check">Method</th>
                        <th class="check">Path</th>
                        <th>Result</th>
                    </tr>
                </thead>
                <tbody>
                    @include('jwtauthorize::_evaluation_tree', ['nodes' => $evaluation->nodes, 'depth' => 0, 'parentMatched' => true])
                </tbody>
            </table>
        </div>
        <p class="hint">
            Highlighted rows are the decision path. Children refine their parent; among matching siblings the first
            <code>deny</code> decides, otherwise the first matching <code>allow</code> does. Faded rows were never checked.
        </p>
    @endif
@endsection
