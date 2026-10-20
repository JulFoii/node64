<?php
// Test-Stub fuer header.php: angemeldet als Account ?as=<id> (Standard 1, 0 = abgemeldet). Nicht hochladen.
if(getenv('HP3ATEST') !== '1') { exit; }
include(__DIR__ . '/dbconnect.php');
session_start();
$userid = isset($_GET['as']) ? (string)(int)$_GET['as'] : '1';
if($userid === '0') { $userid = ''; }
echo "<html><body>\n";
