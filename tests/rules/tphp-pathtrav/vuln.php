<?php
function handler($db) {
    $value = $_GET['v'];
    include($value); // vuln: tphp-pathtrav
}
function upload_name() {
    $name = $_FILES['file']['name'];
    echo file_get_contents("/var/www/uploads/" . $name); // vuln: tphp-pathtrav
}
