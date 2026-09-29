<?php
function handler($db) {
    $value = $_GET['v'];
    $c = curl_init($value); // vuln: tphp-ssrf
}
