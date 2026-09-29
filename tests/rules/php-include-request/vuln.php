<?php
include $_GET['page']; // vuln: php-include-request
require 'pages/' . $_POST['p'] . '.php'; // vuln: php-include-request
include_once $_REQUEST['f']; // vuln: php-include-request
