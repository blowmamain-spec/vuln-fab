<?php
function handler($db) {
    $value = $_GET['v'];
    unserialize($value); // vuln: tphp-deser
}
