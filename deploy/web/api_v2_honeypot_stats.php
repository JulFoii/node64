<?php
/**
 * IPv64.net API v2 – oeffentliche Statistik Honeypot64 (Phase H4). Wird von api_v2.php vor dispatch() eingebunden,
 * nach api_v2_threat.php:
 *     require __DIR__ . '/api_v2_honeypot_stats.php';
 * Gemeinsame Logik mit der Seite honeypot/stats.php: honeypot/hp_stats_lib.php. Planung: docs/PLAN-NODE64-HONEYPOT64.md
 * (Abschnitte 7, 10).
 *
 *   GET /threat/stats   Ueberblick wie auf honeypot/stats.php fuer alle: aktive Sensoren, Angriffe 24 h, Verlauf
 *                       30 Tage, Top 10 Ports/Arten, Groesse der Listen, Top 10 Benutzernamen/Passwoerter/Pfade/
 *                       User-Agents (nur ab N Accounts). Ohne API-Key erlaubt (Limit wie /threat/ip je Client-IP),
 *                       mit API-Key je Account. Antwort aus dem Cache (hoechstens alle 10 Minuten neu gerechnet).
 */
require_once __DIR__ . '/honeypot/hp_release_lib.php';
require_once __DIR__ . '/honeypot/hp_stats_lib.php';

/** GET /threat/stats: oeffentlicher Ueberblick. */
route('GET', '/threat/stats', function() {
	global $pdo;
	$tok = bearer();
	if($tok !== null AND $tok !== '') {
		authenticate();
		rl_enforce('threatstats:user:' . uid(), HPR_RL_KEY_CAP, HPR_RL_KEY_REFILL, 'statistics');
	} else {
		rl_enforce('threatstats:anon:' . client_ip(), HPR_RL_ANON_CAP, HPR_RL_ANON_REFILL, 'statistics without API key');
	}
	try {
		$o = hps_overview($pdo, __DIR__ . '/blocklists');
	} catch(Throwable $e) {
		error_log('api_v2 threat/stats: ' . $e->getMessage());
		fail(503, 'unavailable', 'The statistics are temporarily unavailable.');
	}
	ok(hps_public($o));
}, true);
