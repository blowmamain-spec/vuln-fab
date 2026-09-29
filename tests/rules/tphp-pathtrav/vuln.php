<?php
function handler($db) {
    $value = $_GET['v'];
    include($value); // vuln: tphp-pathtrav
}
