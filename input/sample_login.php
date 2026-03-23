<?php
/**
 * sample_login.php — PHP 7.4 dummy file for pipeline testing.
 * Contains intentional vulnerabilities: SQL Injection, XSS, hardcoded credentials.
 */

// Hardcoded credentials (ISO A.5.17)
$db_host = "localhost";
$db_user = "root";
$db_pass = "admin123";
$db_name = "ugm_portal";

$conn = mysql_connect($db_host, $db_user, $db_pass);
mysql_select_db($db_name, $conn);

$username = $_POST['username'];
$password = $_POST['password'];

// SQL Injection (ISO A.8.28, A.8.26)
$query = "SELECT * FROM users WHERE username = '$username' AND password = '$password'";
$result = mysql_query($query, $conn);

if (mysql_num_rows($result) > 0) {
    $user = mysql_fetch_assoc($result);
    $_SESSION['user_id'] = $user['id'];

    // XSS (ISO A.8.28, A.8.26)
    echo "<h2>Welcome, " . $_GET['name'] . "!</h2>";
    echo "<p>Your role: " . $user['role'] . "</p>";
} else {
    echo "Invalid credentials.";
}

mysql_close($conn);
