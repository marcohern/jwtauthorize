@extends('jwtauthorize::layout')

@section('title', 'New role')

@section('content')
    <div class="bar">
        <h1>New role</h1>
    </div>

    @include('jwtauthorize::roles._form', ['action' => route('jwtauthorize.roles.store'), 'rows' => $rows])
@endsection
