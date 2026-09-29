<h1>{{ $post->title }}</h1>

{{-- @lab vuln blade-raw cwe=CWE-79 tier=A :: isi post dicetak tanpa escape --}}
<div>{!! $post->body !!}</div>

{{-- @lab decoy blade-raw cwe=CWE-79 :: di-escape lewat e() --}}
<div>{!! e($post->body) !!}</div>

{{-- @lab decoy blade-raw cwe=CWE-79 :: {{ }} otomatis di-escape --}}
<p>{{ $post->title }}</p>

{{-- @lab vuln blade-csrf cwe=CWE-352 tier=A :: form POST tanpa @csrf --}}
<form method="POST" action="/posts">
    <input name="title">
</form>

{{-- @lab decoy blade-csrf cwe=CWE-352 :: @csrf ada --}}
<form method="POST" action="/posts-safe">
    @csrf
    <input name="title">
</form>
