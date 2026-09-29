<form method="POST" action="/posts">  {{-- vuln: lv-blade-csrf --}}
    <input name="title">
</form>
