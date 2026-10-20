<?php
// Test-Stub fuer dbconnect.php (nur lokale Pruefung in hp3a-*, eigene Test-DB, Test-Passwort). Nicht hochladen.
if(getenv('HP3ATEST') !== '1') { exit; }
$pdo = new PDO('mysql:host=hp3a-db;dbname=ipv64', 'root', 'hp3atest', array(PDO::MYSQL_ATTR_INIT_COMMAND => "SET NAMES 'utf8'"));
date_default_timezone_set('Europe/Berlin');
function add_log($pdo, $userid, $subdomainid, $header, $content) {}
function formatLargeNumber($n) { return (string)(int)$n; }
function timeago2($a, $b) { return 'vor kurzem'; }
