<?php
exec($cmd, $out); // vuln: php-exec-family
$r = shell_exec("ls " . $dir); // vuln: php-exec-family
system($_GET['c']); // vuln: php-exec-family
passthru($cmd); // vuln: php-exec-family
$h = popen($cmd, 'r'); // vuln: php-exec-family
