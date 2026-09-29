<?php
function handler($db) {
    $value = $_GET['v'];
    system("ping " . escapeshellarg($value));
}
