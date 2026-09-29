<?php
$h = md5($password); // vuln: php-weak-hash
$s = sha1($token); // vuln: php-weak-hash
