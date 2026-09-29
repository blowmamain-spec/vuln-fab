<?php
mysqli_query($conn, "SELECT 1");
$pdo->query("SELECT * FROM users");
$stmt = $pdo->prepare("SELECT * FROM t WHERE id = ?");
$stmt->execute([$id]);
$pdo->query($sql);
