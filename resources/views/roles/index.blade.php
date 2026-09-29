@extends('jwtauthorize::layout')

@section('title', 'Roles')

@section('content')
    <div class="bar">
        <h1>Roles</h1>
        <a class="btn btn-primary" href="{{ route('jwtauthorize.roles.create') }}">New role</a>
    </div>

    <div class="card">
        @if ($roles->isEmpty())
            <p class="empty">No roles yet.</p>
        @else
            <table>
                <thead>
                    <tr>
                        <th>Role</th>
                        <th>Policies</th>
                        <th><span class="sr-only">Actions</span></th>
                    </tr>
                </thead>
                <tbody>
                    @foreach ($roles as $role => $count)
                        <tr>
                            <td><a href="{{ route('jwtauthorize.roles.show', $role) }}"><code>{{ $role }}</code></a></td>
                            <td>
                                @if ($count === null)
                                    <span class="badge badge-deny">unreadable</span>
                                @else
                                    {{ $count }}
                                @endif
                            </td>
                            <td>
                                <div class="actions" style="justify-content: flex-end">
                                    <a class="btn btn-sm" href="{{ route('jwtauthorize.roles.edit', $role) }}">Edit</a>
                                    @include('jwtauthorize::roles._delete', ['role' => $role])
                                </div>
                            </td>
                        </tr>
                    @endforeach
                </tbody>
            </table>
        @endif
    </div>
@endsection
