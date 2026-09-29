<?php
function handler($db) {
    $value = $_GET['v'];
    echo "<p>" . $value . "</p>"; // vuln: tphp-xss
}
