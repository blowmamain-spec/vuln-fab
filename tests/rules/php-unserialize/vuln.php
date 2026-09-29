<?php
$o = unserialize($_GET['d']); // vuln: php-unserialize
$p = unserialize(base64_decode($cookie)); // vuln: php-unserialize
