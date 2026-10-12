<?php
/** Healthchecks 2.0 – JSON-Daten fuer Charts der Detailseite (Session-Login). */
ob_start(); // header.php gibt HTML aus; hc2_json() verwirft es
include("../header.php");
require_once(__DIR__ . '/hc2_lib.php');
if ($userid == '') { hc2_json(array('error' => 'login'), 401); }
$uid = (int)$userid;
$c = hc2_check($uid, (string)($_GET['token'] ?? ''));
if (!$c) { hc2_json(array('error' => 'not found'), 404); }
$range = (string)($_GET['range'] ?? '24h');
$nodes = hc2_nodes($uid);
$pdo = hc2_pdo();
$series = array();
try {
	if ($range === '24h' || $range === '6h') {
		$hours = $range === '6h' ? 6 : 24;
		$st = $pdo->prepare("SELECT source, time, status, latency_ms FROM hc2_measurements WHERE token = :t AND time > UTC_TIMESTAMP() - INTERVAL $hours HOUR ORDER BY time LIMIT 6000");
		$st->execute(array('t' => $c['token']));
		foreach ($st->fetchAll(PDO::FETCH_ASSOC) as $m) {
			$series[$m['source']][] = array('t' => hc2_dt($m['time'], 'c'), 'ms' => (int)$m['status'] === 1 ? round((float)$m['latency_ms'], 2) : null, 'ok' => (int)$m['status']);
		}
	} else {
		$days = $range === '7d' ? 7 : ($range === '30d' ? 30 : 365);
		$tbl = $days <= 30 ? 'hc2_hourly' : 'hc2_daily'; $col = $days <= 30 ? 'hour' : 'day'; $unit = $days <= 30 ? 'HOUR' : 'DAY'; $span = $days <= 30 ? $days * 24 : $days;
		$st = $pdo->prepare("SELECT source, $col ts, count, up_count, avg_ms, max_ms FROM $tbl WHERE token = :t AND $col >= UTC_TIMESTAMP() - INTERVAL $span $unit ORDER BY $col");
		$st->execute(array('t' => $c['token']));
		foreach ($st->fetchAll(PDO::FETCH_ASSOC) as $m) {
			$series[$m['source']][] = array('t' => hc2_dt($m['ts'], 'c'), 'ms' => $m['avg_ms'] !== null ? round((float)$m['avg_ms'], 2) : null, 'max' => $m['max_ms'] !== null ? round((float)$m['max_ms'], 2) : null,
				'avail' => (int)$m['count'] > 0 ? round(100 * (int)$m['up_count'] / (int)$m['count'], 2) : null);
		}
	}
} catch (Throwable $e) { error_log('hc2 data: ' . $e->getMessage()); hc2_json(array('error' => 'db'), 500); }
$out = array();
foreach ($series as $src => $pts) { $out[] = array('source' => $src, 'label' => hc2_source_label($src, $nodes), 'points' => $pts); }
hc2_json(array('token' => $c['token'], 'range' => $range, 'series' => $out));
