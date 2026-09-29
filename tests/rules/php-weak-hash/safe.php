<?php
$h = password_hash($password, PASSWORD_DEFAULT);
$s = hash('sha256', $data);
