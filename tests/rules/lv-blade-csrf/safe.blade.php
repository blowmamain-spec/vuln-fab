<form method="POST" action="/posts">
    @csrf
    <input name="title">
</form>
<form method="GET" action="/search"><input name="q"></form>
<form method="POST" action="https://other.example.com/hook"><input name="x"></form>
