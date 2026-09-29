<?php
eval($code); // vuln: php-eval
eval("return " . $expr . ";"); // vuln: php-eval
