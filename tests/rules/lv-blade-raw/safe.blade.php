<h1>{{ $post->title }}</h1>
{!! e($post->body) !!}
{!! '<hr>' !!}
{{-- {!! $hidden !!} --}}
@verbatim
    {!! $vue_or_alpine !!}
@endverbatim
