<?php
// Test-Stub fuer dbconnect.php (nur lokale Pruefung in hp2test-*, eigene Test-DB, Test-Passwort). Nicht hochladen.
if(getenv('HP2TEST') !== '1') { exit; }
$pdo = new PDO('mysql:host=hp2test-db;dbname=ipv64', 'root', 'hp2test', array(PDO::ATTR_PERSISTENT => true, PDO::MYSQL_ATTR_INIT_COMMAND => "SET NAMES 'utf8'"));
date_default_timezone_set('Europe/Berlin');
function add_log($pdo, $userid, $subdomainid, $header, $content) {}
