<p><?= $user->bio ?></p> {{-- vuln: lv-blade-php-echo --}}
@php echo $request->name; @endphp {{-- vuln: lv-blade-php-echo --}}
