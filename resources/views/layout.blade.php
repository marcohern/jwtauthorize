<!doctype html>
<html lang="{{ str_replace('_', '-', app()->getLocale()) }}">
<head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <meta name="csrf-token" content="{{ csrf_token() }}">
    <title>@yield('title', 'Roles') · Jwtauthorize</title>
    <style>
        :root {
            --bg: #f6f7f9; --surface: #fff; --text: #1d2330; --muted: #677084; --border: #dde1e8;
            --accent: #2f5bd3; --accent-text: #fff; --allow: #1f7a4d; --allow-bg: #e3f4ea;
            --deny: #b3261e; --deny-bg: #fbe6e4; --notice-bg: #e8effd;
        }
        @media (prefers-color-scheme: dark) {
            :root {
                --bg: #14171d; --surface: #1c2029; --text: #e6e8ee; --muted: #9aa2b3; --border: #303644;
                --accent: #7c9cf5; --accent-text: #10131a; --allow: #6fd49d; --allow-bg: #173024;
                --deny: #f28b82; --deny-bg: #3a1c1a; --notice-bg: #1d2740;
            }
        }
        * { box-sizing: border-box; }
        body { margin: 0; background: var(--bg); color: var(--text); font: 15px/1.5 system-ui, -apple-system, "Segoe UI", Roboto, sans-serif; }
        header { background: var(--surface); border-bottom: 1px solid var(--border); }
        header .wrap { display: flex; align-items: center; gap: 1rem; padding-block: .75rem; }
        header a { color: var(--text); font-weight: 600; text-decoration: none; }
        .wrap { max-width: 64rem; margin: 0 auto; padding-inline: 1rem; }
        main.wrap { padding-block: 1.5rem 3rem; }
        h1 { font-size: 1.4rem; margin: 0; }
        .bar { display: flex; flex-wrap: wrap; align-items: center; justify-content: space-between; gap: .75rem; margin-bottom: 1rem; }
        .actions { display: flex; flex-wrap: wrap; gap: .5rem; align-items: center; }
        .card { background: var(--surface); border: 1px solid var(--border); border-radius: .5rem; overflow-x: auto; }
        table { width: 100%; border-collapse: collapse; }
        th, td { padding: .55rem .75rem; text-align: left; border-bottom: 1px solid var(--border); vertical-align: middle; }
        tr:last-child td { border-bottom: 0; }
        th { font-size: .8rem; font-weight: 600; color: var(--muted); text-transform: uppercase; letter-spacing: .03em; }
        a { color: var(--accent); }
        code, input.mono { font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace; font-size: .9em; }
        .btn { display: inline-flex; align-items: center; gap: .3rem; padding: .4rem .8rem; border: 1px solid var(--border); border-radius: .375rem;
               background: var(--surface); color: var(--text); font: inherit; font-size: .9rem; text-decoration: none; cursor: pointer; }
        .btn:hover { border-color: var(--accent); }
        .btn-primary { background: var(--accent); border-color: var(--accent); color: var(--accent-text); }
        .btn-danger { color: var(--deny); }
        .btn-sm { padding: .15rem .45rem; font-size: .8rem; min-width: 1.8rem; justify-content: center; }
        .btn:disabled { opacity: .4; cursor: default; }
        form.inline { display: inline; margin: 0; }
        .badge { display: inline-block; min-width: 3.2rem; padding: .05rem .45rem; border-radius: 999px; font-size: .75rem; font-weight: 600; text-align: center; }
        .badge-allow { background: var(--allow-bg); color: var(--allow); }
        .badge-deny { background: var(--deny-bg); color: var(--deny); }
        .notice { padding: .6rem .9rem; border-radius: .375rem; margin-bottom: 1rem; background: var(--notice-bg); }
        .errors { padding: .6rem .9rem; border-radius: .375rem; margin-bottom: 1rem; background: var(--deny-bg); color: var(--deny); }
        .errors ul { margin: 0; padding-left: 1.2rem; }
        .muted { color: var(--muted); }
        .empty { padding: 2rem; text-align: center; color: var(--muted); }
        label { display: block; font-weight: 600; margin-bottom: .3rem; }
        input, select { font: inherit; color: var(--text); background: var(--bg); border: 1px solid var(--border); border-radius: .375rem; padding: .35rem .5rem; }
        input:focus, select:focus { outline: 2px solid var(--accent); outline-offset: -1px; }
        input[readonly] { color: var(--muted); }
        .field { margin-bottom: 1.25rem; }
        .field input { width: min(100%, 22rem); }
        .field-error { color: var(--deny); font-size: .85rem; margin-top: .25rem; }
        .hint { color: var(--muted); font-size: .85rem; margin: .25rem 0 0; }
        .sr-only { position: absolute; width: 1px; height: 1px; overflow: hidden; clip: rect(0 0 0 0); white-space: nowrap; }
    </style>
    @stack('head')
</head>
<body>
<header>
    <div class="wrap">
        <a href="{{ route('jwtauthorize.roles.index') }}">Jwtauthorize · Roles</a>
    </div>
</header>
<main class="wrap">
    @if (session('status'))
        <div class="notice" role="status">{{ session('status') }}</div>
    @endif

    @if ($errors->any())
        <div class="errors" role="alert">
            <ul>
                @foreach ($errors->all() as $error)
                    <li>{{ $error }}</li>
                @endforeach
            </ul>
        </div>
    @endif

    @yield('content')
</main>
@stack('scripts')
</body>
</html>
