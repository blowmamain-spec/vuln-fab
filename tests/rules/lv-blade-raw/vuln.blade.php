<h1>{!! $post->title !!}</h1> {{-- vuln: lv-blade-raw --}}
<div>{!! $comment->body !!}</div> {{-- vuln: lv-blade-raw --}}
