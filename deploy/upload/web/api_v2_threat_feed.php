<?php
/**
 * IPv64.net API v2 – Aenderungs-Feed der v64 Blocklist, Honeypot64 Phase H6. Eingebunden am Ende von
 * api_v2_honeypot.php (keine Aenderung an api_v2.php noetig). Planung: docs/PLAN-NODE64-HONEYPOT64.md (Abschnitte 7, 8).
 *
 *   GET /threat/feed?since=<cursor>   Aenderungen der v64 Blocklist und ihrer Teillisten (Live-Stand) nach dem Cursor,
 *       aelteste zuerst, hoechstens HPF_PAGE je Abruf. Je Aenderung: ip, action (add = neu gelistet, remove = nicht mehr
 *       gelistet, update = andere Teillisten), lists (danach), previous_lists (davor), at (Zeitpunkt der Bewertung, UTC).
 *       next = Cursor fuer den naechsten Abruf (undurchsichtig, enthaelt Zeit und ID), more = es liegen weitere bereit.
 *       Ohne since: aktueller Cursor ohne Eintraege (vorher die Live-Liste vollstaendig laden). ETag/If-None-Match:
 *       unveraendert -> 304. Cursor aelter als HPF_KEEP_DAYS, dessen Aenderungen schon geloescht sind -> 410.
 *       Zugriff wie der Live-Stand: alle Klassen ausser Standard (user_class != 1) und Beitragende (ein Sensor des
 *       Accounts hat in den letzten 7 Tagen gemeldet); sonst 403. Limit je Account wie /threat/ip mit Key.
 *
 * Tabelle hp_list_changes (deploy/sql/honeypot_h6.sql), geschrieben von bots/blocklist/honeypot_score.php in derselben
 * Transaktion wie hp_scores (alle 30 Minuten), Frist 30 Tage.
 */
require_once __DIR__ . '/honeypot/hp_release_lib.php';

const HPF_PAGE      = 10000;      // Aenderungen je Abruf
const HPF_KEEP_DAYS = 30;         // so lange bleiben Aenderungen (honeypot_score.php loescht aeltere)
const HPF_CONTRIB   = 7 * 86400;  // Beitragende: Meldung in den letzten 7 Tagen (wie blocklists/live.php)

/** Cursor (Zeit, ID) -> undurchsichtige Zeichenkette (base64url, 22 Zeichen) */
function hpf_cursor(int $ts, int $id): string { return rtrim(strtr(base64_encode(pack('JJ', $ts, $id)), '+/', '-_'), '='); }

/** Zeichenkette -> array(Zeit, ID) oder null */
function hpf_parse(string $c): ?array {
	if(!preg_match('/^[A-Za-z0-9_-]{22}$/D', $c)) { return null; }
	$b = base64_decode(strtr($c, '-_', '+/') . '==', true);
	if($b === false OR strlen($b) !== 16) { return null; }
	$v = unpack('Jt/Ji', $b);
	if($v['t'] < 0 OR $v['i'] < 0 OR $v['t'] > time() + 86400) { return null; }
	return array((int)$v['t'], (int)$v['i']);
}

/** GET /threat/feed?since=<cursor>: Aenderungen der v64 Blocklist. */
route('GET', '/threat/feed', function() {
	global $ME, $pdo;
	rl_enforce('threatfeed:user:' . uid(), HPR_RL_KEY_CAP, HPR_RL_KEY_REFILL, 'change feed');
	$live = (int)$ME['user_class'] !== 1;
	if(!$live) {
		$live = q1("SELECT 1 x FROM hp_sensors WHERE userid = :u AND disabled = 0 AND last_seen >= :d LIMIT 1", array('u' => uid(), 'd' => gmdate('Y-m-d H:i:s', time() - HPF_CONTRIB))) !== null;
	}
	if(!$live) {
		fail(403, 'feed_not_available', 'The change feed belongs to the live v64 Blocklist: available for all plans except Standard and for contributors '
			. '(a Honeypot64 sensor of your account reported in the last 7 days). Everyone can use the daily list https://ipv64.net/blocklists/ipv64_blocklist_v64.txt.');
	}
	$in = qp('since', '');
	try {
		if($in === '') {
			$last = hpr_one($pdo, "SELECT id, created_at FROM hp_list_changes ORDER BY id DESC LIMIT 1");
			$next = $last === null ? hpf_cursor(time(), 0) : hpf_cursor((int)strtotime($last['created_at'] . ' UTC'), (int)$last['id']);
			$rows = array(); $more = false;
		} else {
			$c = hpf_parse($in);
			if($c === null) { fail(400, 'invalid_parameter', "Query parameter 'since' must be the 'next' value of a previous answer."); }
			[$ts, $sid] = $c;
			if($ts < time() - HPF_KEEP_DAYS * 86400) {
				$min = hpr_one($pdo, "SELECT MIN(id) m FROM hp_list_changes");
				if($min['m'] === null OR (int)$min['m'] > $sid + 1) {
					fail(410, 'cursor_expired', 'This cursor is older than ' . HPF_KEEP_DAYS . ' days and changes after it are gone. Load the full live list again and start without since.');
				}
			}
			$rows = hpr_all($pdo, "SELECT id, created_at, action, ip, lists, prev_lists FROM hp_list_changes WHERE id > :id ORDER BY id LIMIT " . (HPF_PAGE + 1), array('id' => $sid));
			$more = count($rows) > HPF_PAGE;
			if($more) { array_pop($rows); }
			$next = $rows ? hpf_cursor((int)strtotime($rows[count($rows) - 1]['created_at'] . ' UTC'), (int)$rows[count($rows) - 1]['id']) : $in;
		}
	} catch(ApiError $e) {
		throw $e;
	} catch(Throwable $e) {
		error_log('api_v2 threat/feed: ' . $e->getMessage());
		fail(503, 'unavailable', 'The change feed is temporarily unavailable.');
	}
	$etag = '"' . substr(sha1($in . '>' . $next), 0, 32) . '"';
	$inm = (string)($_SERVER['HTTP_IF_NONE_MATCH'] ?? '');
	if($inm !== '' AND in_array($etag, array_map('trim', explode(',', $inm)), true)) {
		while(ob_get_level() > 0) { ob_end_clean(); }
		http_response_code(304);
		header('ETag: ' . $etag);
		header('Cache-Control: private, no-cache');
		header('X-API-Version: ' . API_VERSION);
		exit;
	}
	header('ETag: ' . $etag);
	$csv = fn($s) => $s === '' ? array() : explode(',', $s);
	ok(array('changes' => array_map(fn($r) => array('ip' => $r['ip'], 'action' => $r['action'], 'lists' => $csv((string)$r['lists']),
		'previous_lists' => $csv((string)$r['prev_lists']), 'at' => gmdate('Y-m-d\TH:i:s\Z', (int)strtotime($r['created_at'] . ' UTC'))), $rows),
		'next' => $next, 'more' => $more));
});
