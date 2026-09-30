<?php
function handler($db) {
    $value = $_GET['v'];
    include("pages/" . basename($value));
}
function upload_tmp() {
    // tmp_name is chosen by PHP, not by the client
    $tmp = $_FILES['file']['tmp_name'];
    echo file_get_contents($tmp);
    echo file_get_contents($_FILES['file']['tmp_name']);
}
