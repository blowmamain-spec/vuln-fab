<?php
function handler($db) {
    $value = $_GET['v'];
    eval("return " . intval($value) . ";");
}
