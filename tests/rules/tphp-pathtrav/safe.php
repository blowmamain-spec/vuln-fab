<?php
function handler($db) {
    $value = $_GET['v'];
    include("pages/" . basename($value));
}
