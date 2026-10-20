<?php
// Test-Stub fuer header.php: Sitzung wie im Portal, angemeldet als Account ?as=<id> (Standard 0 = nicht angemeldet). Nicht hochladen.
if(getenv('HP3BTEST') !== '1') { exit; }
include(__DIR__ . '/dbconnect.php');
session_start();
$userid = isset($_GET['as']) ? (string)(int)$_GET['as'] : '';
if($userid === '0') { $userid = ''; }
if($userid !== '') { $st = $pdo->prepare("SELECT * FROM users WHERE id = ?"); $st->execute(array($userid)); $account = $st->fetch(); if($account === false) { $userid = ''; unset($account); } }
echo "<html><body>\n";
