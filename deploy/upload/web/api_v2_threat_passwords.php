<?php
/**
 * IPv64.net API v2 – Passwortpruefung mit k-Anonymitaet (wie Have I Been Pwned), Honeypot64 Phase H6. Eingebunden am
 * Ende von api_v2_honeypot.php (keine Aenderung an api_v2.php noetig). Planung: docs/PLAN-NODE64-HONEYPOT64.md (Abschnitt 7).
 *
 *   GET /threat/passwords/range/{prefix}   prefix = die ersten 5 Hex-Zeichen von SHA-1(Passwort), gross oder klein.
 *       Antwort text/plain, je Zeile "<restliche 35 Hex, gross>:<Anzahl>", sortiert. Enthalten sind alle Passwoerter,
 *       die Angreifer in den letzten 365 Tagen an Honeypot64-Sensoren probiert haben und die die Mehrfach-Account-
 *       Schwelle erfuellt haben (honeypot/hp_stats_lib.php, mindestens 2 bzw. 3 unabhaengige Accounts in 30 Tagen).
 *       Aufgefuellt mit Zufallszeilen (Anzahl 0) auf mindestens HPP_PAD_MIN Zeilen, damit die Groesse der Antwort
 *       nichts verraet. Das Passwort und sein voller Hash verlassen nie den Client.
 *       Ohne API-Key frei (Limit je Client-IP wie /threat/ip), mit API-Key je Account. Cache 1 h.
 *
 * Tabelle hp_pw_range (deploy/sql/honeypot_h6.sql), gepflegt von bots/honeypot_passwords.php (Job pwrange in
 * bots/honeypot_cron.php); Abfrage als Bereich ueber den Primaerschluessel.
 */
require_once __DIR__ . '/honeypot/hp_release_lib.php';

const HPP_PAD_MIN = 64;    // mindestens so viele Zeilen je Antwort (echte + Zufallszeilen mit Anzahl 0)
const HPP_MAX_AGE = 3600;  // Cache-Control max-age

/** GET /threat/passwords/range/{prefix}: Hash-Endungen zu einem SHA-1-Praefix. */
route('GET', '/threat/passwords/range/{prefix}', function($p) {
	$tok = bearer();
	if($tok !== null AND $tok !== '') {
		authenticate();
		rl_enforce('threatpw:user:' . uid(), HPR_RL_KEY_CAP, HPR_RL_KEY_REFILL, 'password checks');
	} else {
		rl_enforce('threatpw:anon:' . client_ip(), HPR_RL_ANON_CAP, HPR_RL_ANON_REFILL, 'password checks without API key');
	}
	$prefix = strtoupper((string)($p['prefix'] ?? ''));
	if(!preg_match('/^[0-9A-F]{5}$/D', $prefix)) { fail(422, 'invalid_prefix', 'Give exactly the first 5 hex characters of the SHA-1 hash of the password.', array('field' => 'prefix')); }
	try {
		$rows = qa("SELECT HEX(sha1) h, cnt FROM hp_pw_range WHERE sha1 BETWEEN UNHEX(:lo) AND UNHEX(:hi) ORDER BY sha1",
			array('lo' => $prefix . str_repeat('0', 35), 'hi' => $prefix . str_repeat('F', 35)));
	} catch(Throwable $e) {
		error_log('api_v2 threat/passwords: ' . $e->getMessage());
		fail(503, 'unavailable', 'The password check is temporarily unavailable.');
	}
	$lines = array();
	foreach($rows as $r) { $lines[substr(strtoupper($r['h']), 5)] = (int)$r['cnt']; }
	// Zufallszeilen (Anzahl 0), nie gleich einer echten Endung
	while(count($lines) < HPP_PAD_MIN) {
		$s = substr(strtoupper(bin2hex(random_bytes(18))), 0, 35);
		if(!isset($lines[$s])) { $lines[$s] = 0; }
	}
	ksort($lines, SORT_STRING);
	$out = '';
	foreach($lines as $s => $c) { $out .= $s . ':' . $c . "\r\n"; }

	while(ob_get_level() > 0) { ob_end_clean(); }
	http_response_code(200);
	header('Content-Type: text/plain; charset=utf-8');
	header('Cache-Control: public, max-age=' . HPP_MAX_AGE);
	header('X-Content-Type-Options: nosniff');
	header('X-API-Version: ' . API_VERSION);
	header('Access-Control-Allow-Origin: *');
	echo $out;
	exit;
}, true);
