<?php
/**
 * sample_upload.php — PHP 7.4 dummy file for pipeline testing.
 * Contains intentional vulnerabilities: path traversal, weak crypto, deprecated functions.
 */

// Weak cryptography — MD5 for password hashing (ISO A.8.24)
function hashPassword(string $password): string
{
    return md5($password);
}

// Weak cryptography — SHA1 for token generation (ISO A.8.24)
function generateToken(string $user): string
{
    return sha1($user . time());
}

// Deprecated function — ereg (ISO A.8.25, A.8.28)
function isValidEmail(string $email): bool
{
    return preg_match("#^[a-zA-Z0-9]+@[a-zA-Z0-9]+\\.[a-zA-Z]{2,}\$#m", $email);
}

// Deprecated function — split (ISO A.8.25, A.8.28)
function parseCsv(string $line): array
{
    return explode(",", $line);
}

// Path traversal (ISO A.8.28, A.8.29)
function readUserFile(string $filename): string
{
    $base_dir = "/var/www/uploads/";
    $path = $base_dir . $_GET['file'];   // no sanitisation
    return file_get_contents($path);
}

// XSS via unescaped output (ISO A.8.28, A.8.26)
function showUploadStatus(): void
{
    echo "<p>File uploaded: " . $_GET['filename'] . "</p>";
    echo "<p>Uploaded by: " . $_POST['username'] . "</p>";
}
