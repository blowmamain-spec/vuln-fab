<?php
function handler($db) {
    $value = $_GET['v'];
    system("ping " . $value); // vuln: tphp-cmdi
}
