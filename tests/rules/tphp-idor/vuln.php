<?php
function handler($db) {
    $value = $_GET['v'];
    $o = Order::find($value); // vuln: tphp-idor
}
