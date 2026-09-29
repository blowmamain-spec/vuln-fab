<?php
$o = json_decode($data);
$p = unserialize($data, ['allowed_classes' => false]);
$s = serialize($obj);
