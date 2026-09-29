<?php
function handler($db) {
    $value = $_GET['v'];
    echo "<p>" . htmlspecialchars($value) . "</p>";
}
