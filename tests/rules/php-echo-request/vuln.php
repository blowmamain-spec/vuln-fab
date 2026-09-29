<?php
echo $_GET['q']; // vuln: php-echo-request
echo $_POST['name']; // vuln: php-echo-request
echo $_REQUEST['x']; // vuln: php-echo-request
