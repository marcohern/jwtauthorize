@extends('jwtauthorize::layout')

@section('title', "Edit $role")

@section('content')
    <div class="bar">
        <h1>Edit role <code>{{ $role }}</code></h1>
    </div>

    @include('jwtauthorize::roles._form', ['action' => route('jwtauthorize.roles.update', $role), 'role' => $role, 'rows' => $rows])
@endsection
