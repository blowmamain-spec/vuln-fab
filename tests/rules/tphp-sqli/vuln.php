<?php
function handler($db) {
    $value = $_GET['v'];
    mysqli_query($db, "select * from t where id = " . $value); // vuln: tphp-sqli
}
