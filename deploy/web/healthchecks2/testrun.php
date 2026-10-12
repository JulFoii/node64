<?php
/** Healthchecks 2.0 – Status eines Testlaufs (JSON, Session-Login). Bei "ok" wird der Wechsel genau einmal angewendet. */
ob_start(); // header.php gibt HTML aus; hc2_json() verwirft es
include("../header.php");
require_once(__DIR__ . '/hc2_lib.php');
if ($userid == '') { hc2_json(array('error' => 'login'), 401); }
try { hc2_json(hc2_testrun_status((int)$userid, (int)($_GET['id'] ?? 0))); }
catch (Throwable $e) { error_log('hc2 testrun: ' . $e->getMessage()); hc2_json(array('status' => 'error', 'error' => 'Datenbankfehler'), 500); }
