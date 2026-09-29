<?php
function handler($db) {
    $value = $_GET['v'];
    redirect($value); // vuln: tphp-redirect
}
