<?php
// Test-Stub fuer dbconnect.php (nur lokale Pruefung in hp6i-*, eigene Test-DB, Test-Passwort). Nicht hochladen.
if(getenv('HP6ITEST') !== '1') { exit; }
$pdo = new PDO('mysql:host=hp6i-db;dbname=ipv64', 'root', 'hp6itest', array(PDO::ATTR_PERSISTENT => true, PDO::MYSQL_ATTR_INIT_COMMAND => "SET NAMES 'utf8'"));
date_default_timezone_set('Europe/Berlin');
function add_log($pdo, $userid, $subdomainid, $header, $content) {}
function formatLargeNumber($n) { return (string)(int)$n; }
function timeago2($a, $b) { return 'vor kurzem'; }
