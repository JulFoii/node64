<?php
/**
 * Honeypot64 (H3): automatische Pruefung der Freigabe-Antraege (Plan Abschnitt 9) und Fristen. Stuendlich per Cron,
 * nur auf der Kommandozeile:
 *
 *   php honeypot_release.php            ausfuehren
 *   php honeypot_release.php --dry      nur anzeigen (keine Aenderung, keine Mail)
 *
 * Je bestaetigtem offenen Antrag (status open, confirmed_at gesetzt):
 *   - eskaliert (status escalated, Grund in note, Mail an Dennis/Admins), wenn
 *       a) die IP seit der Bestaetigung wieder einen Sensor beruehrt hat (hp_report_sources.last_seen > confirmed_at),
 *       b) es fuer dieselbe IP in den letzten 90 Tagen weitere bestaetigte Antraege gibt,
 *       c) derselbe Absender (E-Mail bzw. Account) in 30 Tagen Antraege fuer 5 oder mehr verschiedene IPs gestellt hat,
 *       d) die IP in einem Provider-/Cloud-Netz liegt (blocklisten.category = 'cloud', z. B. AWS, Google Cloud);
 *   - sonst nach 24 h ab der Bestaetigung freigegeben: status released, protected_until = +30 Tage, Eintrag in
 *     hp_allowlist (source request, until = protected_until), Bescheid an den Antragsteller. Die Bewertung uebernimmt
 *     die Freigabe beim naechsten Lauf (liest hp_allowlist), die Auskunft sofort.
 * Fristen: unbestaetigte Antraege nach 48 h loeschen, client_hash nach 2 Tagen leeren, E-Mail 90 Tage nach der
 * Entscheidung leeren, entschiedene Antraege nach 365 Tagen loeschen, abgelaufene request-Freigaben nach 7 Tagen loeschen.
 */
if(php_sapi_name() !== 'cli') { exit; }
include(__DIR__ . "/../dbconnect.php");
require_once __DIR__ . '/../honeypot/hp_release_lib.php';

$dry = in_array('--dry', $argv, true);
$now = time();
echo ($dry ? "NUR ANZEIGEN" : "AUSFUEHREN") . ": " . gmdate('Y-m-d H:i:s', $now) . " UTC\n";
if((int)(hpr_one($pdo, "SELECT GET_LOCK('hp_release', 0) l")['l'] ?? 0) !== 1) { echo "laeuft bereits\n"; exit(0); }

// ---------------------------------------------------------------- Pruefung
$stat = array('released' => 0, 'escalated' => 0, 'waiting' => 0);
$admins = null;
foreach(hpr_all($pdo, "SELECT * FROM hp_release_requests WHERE status = 'open' AND confirmed_at IS NOT NULL ORDER BY id") as $r) {
	$b = bin2hex($r['ip_bin']); $conf = (int)hpr_ts($r['confirmed_at']);
	$why = array();
	$t = hpr_one($pdo, "SELECT COUNT(*) n, MAX(last_seen) l, COUNT(DISTINCT userid) a FROM hp_report_sources WHERE ip_bin = UNHEX(:b) AND last_seen > :c", array('b' => $b, 'c' => $r['confirmed_at']));
	if((int)$t['n'] > 0) { $why[] = 'greift weiter an: ' . (int)$t['n'] . ' Meldungen von ' . (int)$t['a'] . ' Accounts seit der Bestaetigung, zuletzt ' . $t['l'] . ' UTC'; }
	$o = (int)hpr_one($pdo, "SELECT COUNT(*) c FROM hp_release_requests WHERE ip_bin = UNHEX(:b) AND id != :id AND confirmed_at IS NOT NULL AND created_at >= :d",
		array('b' => $b, 'id' => $r['id'], 'd' => hpr_dt($now - HPR_HISTORY_DAYS * 86400)))['c'];
	if($o > 0) { $why[] = 'mehrere Antraege: ' . $o . ' weitere fuer diese IP in ' . HPR_HISTORY_DAYS . ' Tagen'; }
	$s = $r['userid'] !== null
		? (int)hpr_one($pdo, "SELECT COUNT(DISTINCT ip_bin) c FROM hp_release_requests WHERE userid = :u AND created_at >= :d", array('u' => $r['userid'], 'd' => hpr_dt($now - HPR_SENDER_DAYS * 86400)))['c']
		: ($r['email'] === '' ? 0 : (int)hpr_one($pdo, "SELECT COUNT(DISTINCT ip_bin) c FROM hp_release_requests WHERE email = :e AND created_at >= :d", array('e' => $r['email'], 'd' => hpr_dt($now - HPR_SENDER_DAYS * 86400)))['c']);
	if($s >= HPR_SENDER_MAX_IPS) { $why[] = 'Absender mit Antraegen fuer ' . $s . ' verschiedene IPs in ' . HPR_SENDER_DAYS . ' Tagen'; }
	$prov = hpr_provider($pdo, $r['ip_bin']);
	if($prov !== null) { $why[] = 'Provider-Netz: ' . $prov; }

	if(!empty($why)) {
		$stat['escalated']++;
		echo "#{$r['id']} {$r['ip']}: eskaliert (" . implode('; ', $why) . ")\n";
		if($dry) { continue; }
		$note = ($r['note'] !== '' ? $r['note'] . "\n" : '') . 'Eskaliert ' . gmdate('Y-m-d H:i', $now) . ' UTC: ' . implode('; ', $why);
		hpr_q($pdo, "UPDATE hp_release_requests SET status = 'escalated', note = :n WHERE id = :id AND status = 'open'", array('n' => mb_substr($note, 0, 2000), 'id' => $r['id']));
		$admins = $admins ?? hpr_admin_mails($pdo);
		foreach($admins as $to) {
			hpr_mail($pdo, $to, "Honeypot64: Freigabe-Antrag #{$r['id']} fuer {$r['ip']} braucht eine Entscheidung",
				"Der Freigabe-Antrag #{$r['id']} fuer {$r['ip']} konnte nicht automatisch entschieden werden.\n\nGruende:\n- " . implode("\n- ", $why)
				. "\n\nBegruendung des Antragstellers:\n" . $r['reason'] . "\n\nEntscheiden: " . HPR_ADMIN_URL);
		}
	} elseif($conf <= $now - HPR_QUIET) {
		$stat['released']++;
		echo "#{$r['id']} {$r['ip']}: freigegeben bis " . gmdate('Y-m-d H:i', $now + HPR_PROTECT_DAYS * 86400) . " UTC\n";
		if($dry) { continue; }
		hpr_release($pdo, $r, HPR_PROTECT_DAYS, null, ($r['note'] !== '' ? $r['note'] . "\n" : '') . 'automatisch: 24 h ohne Beruehrung seit der Bestaetigung');
		$x = hpr_one($pdo, "SELECT * FROM hp_release_requests WHERE id = :id", array('id' => $r['id']));
		hpr_mail_decision($pdo, $x, 'released', $x['protected_until']);
	} else {
		$stat['waiting']++;
	}
}
echo "Antraege: {$stat['released']} freigegeben, {$stat['escalated']} eskaliert, {$stat['waiting']} warten\n";

// ---------------------------------------------------------------- Fristen
$steps = array(
	'unbestaetigte Antraege geloescht' => array("DELETE FROM hp_release_requests WHERE confirmed_at IS NULL AND created_at < :d", $now - HPR_CONFIRM_TTL),
	'client_hash geleert' => array("UPDATE hp_release_requests SET client_hash = '' WHERE client_hash != '' AND created_at < :d", $now - 2 * 86400),
	'E-Mail geleert' => array("UPDATE hp_release_requests SET email = '' WHERE email != '' AND decided_at IS NOT NULL AND decided_at < :d", $now - 90 * 86400),
	'entschiedene Antraege geloescht' => array("DELETE FROM hp_release_requests WHERE status IN ('released', 'rejected') AND decided_at < :d", $now - 365 * 86400),
	'abgelaufene Freigaben aus Antraegen geloescht' => array("DELETE FROM hp_allowlist WHERE source = 'request' AND `until` IS NOT NULL AND `until` < :d", $now - 7 * 86400),
);
foreach($steps as $what => [$sql, $ts]) {
	if($dry) {
		$cnt = preg_replace(array('/^DELETE FROM (\S+) WHERE/', "/^UPDATE (\S+) SET \S+ = '' WHERE/"), 'SELECT COUNT(*) c FROM $1 WHERE', $sql);
		echo "$what: " . (int)hpr_one($pdo, $cnt, array('d' => hpr_dt($ts)))['c'] . " (nur angezeigt)\n";
	} else {
		echo "$what: " . hpr_q($pdo, $sql, array('d' => hpr_dt($ts)))->rowCount() . "\n";
	}
}
hpr_q($pdo, "SELECT RELEASE_LOCK('hp_release')");
