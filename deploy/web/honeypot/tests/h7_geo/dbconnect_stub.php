<?php
// Test-Stub fuer dbconnect.php (nur lokale Pruefung in hp7g-*, eigene Test-DB, Test-Passwort). Nicht hochladen.
if(getenv('HP7GTEST') !== '1') { exit; }
$pdo = new PDO('mysql:host=hp7g-db;dbname=ipv64', 'root', 'hp7gtest', array(PDO::ATTR_PERSISTENT => true, PDO::MYSQL_ATTR_INIT_COMMAND => "SET NAMES 'utf8'"));
date_default_timezone_set('Europe/Berlin');
function add_log($pdo, $userid, $subdomainid, $header, $content) {}
function formatLargeNumber($n) { return (string)(int)$n; }
function timeago2($a, $b) { return 'vor kurzem'; }
