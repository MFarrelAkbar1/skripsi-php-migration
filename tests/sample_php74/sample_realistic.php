<?php
/**
 * sample_realistic.php — PHP 5 realistic web page for pipeline testing.
 *
 * Simulates a typical DTI UGM portal page (login + profile display).
 * Deliberately mixes Rector-fixable and non-fixable PHP 5 constructs so
 * the pipeline produces a conversion rate representative of real-world code.
 *
 * Rector-fixable constructs (4 items):
 *   - Old-style PHP 5 constructor    → __construct()   Php4ConstructorRector
 *   - array() literal × 2            → []              CodeQuality/ShortArrays
 *   - ereg()                          → preg_match()   EregrToPregMatchRector
 *   - split()                         → explode()      SplitToExplodeRector
 *
 * Non-fixable by Rector (4 items):
 *   - mysql_connect()                 ext/mysql removed PHP 7.0 (ISO A.8.28)
 *   - mysql_query()                   ext/mysql removed PHP 7.0 (ISO A.8.28)
 *   - md5() for password hashing      weak crypto (ISO A.8.24)
 *   - echo with unescaped $_POST      XSS (ISO A.8.28, A.8.26)
 */

// ---------------------------------------------------------------------------
// PHP 5 old-style constructor — Rector CAN fix → __construct()
// ---------------------------------------------------------------------------

class PageRenderer
{
    private $title;
    private $lang;

    // PHP 4/5 style: constructor named after the class (deprecated PHP 7.0)
    function PageRenderer($title, $lang = 'id')
    {
        $this->title = $title;
        $this->lang  = $lang;
    }

    public function renderHead()
    {
        return '<meta charset="UTF-8"><title>' . $this->title . '</title>';
    }
}

// ---------------------------------------------------------------------------
// PHP 5 array() literals — Rector CAN fix → [] short syntax
// ---------------------------------------------------------------------------

$allowed_roles = array('admin', 'dosen', 'mahasiswa');         // array #1

$page_config = array(                                           // array #2
    'title'   => 'Portal DTI UGM',
    'version' => '2.1',
    'lang'    => 'id',
);

// ---------------------------------------------------------------------------
// ereg() input validation — Rector CAN fix → preg_match()
// ---------------------------------------------------------------------------

$nim = $_POST['nim'] ?? '';

if (!ereg('^[0-9]{8,12}$', $nim)) {
    die('NIM tidak valid.');
}

// ---------------------------------------------------------------------------
// split() for URI parsing — Rector CAN fix → explode()
// ---------------------------------------------------------------------------

$uri_parts   = split('/', ltrim($_SERVER['REQUEST_URI'] ?? '', '/'));
$active_menu = !empty($uri_parts[0]) ? $uri_parts[0] : 'beranda';

// ---------------------------------------------------------------------------
// mysql_* calls — Rector CANNOT fix (ext/mysql removed PHP 7.0)
// ---------------------------------------------------------------------------

$conn   = mysql_connect('localhost', 'dti_user', 'pass123');
$result = mysql_query(
    "SELECT nama, role FROM mahasiswa WHERE nim = '$nim'",
    $conn
);

// ---------------------------------------------------------------------------
// MD5 password hash — Rector CANNOT fix (weak crypto, ISO A.8.24)
// ---------------------------------------------------------------------------

$hashed_pass = md5($_POST['password'] ?? '');

// ---------------------------------------------------------------------------
// Output with unescaped POST variable — Rector CANNOT fix (XSS, ISO A.8.26)
// ---------------------------------------------------------------------------

$renderer = new PageRenderer($page_config['title'], $page_config['lang']);
echo $renderer->renderHead();

if ($result && mysql_num_rows($result) > 0) {
    $row = mysql_fetch_assoc($result);

    echo '<p>Selamat datang, ' . $_POST['nim'] . '!</p>';   // XSS
    echo '<p>Nama  : ' . $row['nama']  . '</p>';
    echo '<p>Role  : ' . $row['role']  . '</p>';
    echo '<p>Menu  : ' . $active_menu  . '</p>';
}

mysql_close($conn);
