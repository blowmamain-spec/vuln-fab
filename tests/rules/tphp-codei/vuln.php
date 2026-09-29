<?php
function handler($db) {
    $value = $_GET['v'];
    eval($value); // vuln: tphp-codei
}
