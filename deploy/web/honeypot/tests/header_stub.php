<?php
// Test-Stub fuer header.php: angemeldet als Account ?as=<id> (Standard 1). Nicht hochladen.
if(getenv('HP2TEST') !== '1') { exit; }
include(__DIR__ . '/dbconnect.php');
$userid = isset($_GET['as']) ? (string)(int)$_GET['as'] : '1';
if($userid === '0') { $userid = ''; }
echo "<html><body>\n";
