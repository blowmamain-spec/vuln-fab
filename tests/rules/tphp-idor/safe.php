<?php
function handler($db) {
    $value = $_GET['v'];
    $owner = auth()->id();
    $o = Order::find($value);
}
