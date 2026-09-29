<?php
mysqli_query($conn, "SELECT * FROM users WHERE id = " . $id); // vuln: php-sql-interp
mysqli_query($conn, "SELECT * FROM users WHERE name = '$name'"); // vuln: php-sql-interp
$pdo->query("SELECT * FROM t WHERE a = " . $a); // vuln: php-sql-interp
$pdo->exec("DELETE FROM t WHERE id = $id"); // vuln: php-sql-interp
