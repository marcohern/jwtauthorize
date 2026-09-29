@extends('jwtauthorize::layout')

@section('title', $role)

@section('content')
    <div class="bar">
        <h1>Role <code>{{ $role }}</code></h1>
        <div class="actions">
            <a class="btn" href="{{ route('jwtauthorize.roles.index') }}">All roles</a>
            <a class="btn btn-primary" href="{{ route('jwtauthorize.roles.edit', $role) }}">Edit</a>
            @include('jwtauthorize::roles._delete', ['role' => $role, 'small' => false])
        </div>
    </div>

    <div class="card">
        @if ($policies->isEmpty())
            <p class="empty">This role has no policies.</p>
        @else
            <table>
                <thead>
                    <tr>
                        <th>Action</th>
                        <th>Methods</th>
                        <th>Path regex</th>
                        <th><span class="sr-only">Order</span></th>
                    </tr>
                </thead>
                <tbody>
                    @include('jwtauthorize::roles._tree', ['policies' => $policies, 'depth' => 0])
                </tbody>
            </table>
        @endif
    </div>
    <p class="hint">Children refine their parent. Among matching siblings, deny wins, so order does not change decisions.</p>
@endsection
