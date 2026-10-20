<?php
// Test-Stub fuer header.php: Sitzung wie im Portal, angemeldet als Account ?as=<id> (ohne = nicht angemeldet). Nicht hochladen.
if(getenv('HP4ATEST') !== '1') { exit; }
include(__DIR__ . '/dbconnect.php');
session_start();
$userid = isset($_GET['as']) ? (string)(int)$_GET['as'] : '';
if($userid === '0') { $userid = ''; }
echo "<html><body>\n";
