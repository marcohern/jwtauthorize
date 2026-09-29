<form class="inline" method="POST" action="{{ route('jwtauthorize.roles.destroy', $role) }}"
      onsubmit="return confirm(@js("Delete role [$role]? Tokens already issued keep its policies."))">
    @csrf
    @method('DELETE')
    <button class="btn {{ $small ?? true ? 'btn-sm' : '' }} btn-danger" type="submit">Delete</button>
</form>
