<?php
/**
 * Honeypot64 (H6): Tabelle hp_pw_range fuer die Passwortpruefung mit k-Anonymitaet (GET /threat/passwords/range/{prefix},
 * api_v2_threat_passwords.php, Seite honeypot/password.php). Job pwrange in bots/honeypot_cron.php, nur Kommandozeile:
 *
 *   php honeypot_passwords.php          Tabelle pflegen
 *   php honeypot_passwords.php --dry    nur rechnen und Zahlen ausgeben
 *
 * Aufnahme: Passwoerter (SHA-1 aus hp_samples_creds.pass_sha1), die die Mehrfach-Account-Schwelle erfuellen
 * (honeypot/hp_stats_lib.php: mindestens N verschiedene Accounts in den letzten 30 Tagen, wie die Ranglisten; die
 * Beitraege je Account hp_sample_contrib reichen nur 35 Tage zurueck). updated = letzter Lauf, in dem die Schwelle
 * erfuellt war; nach 365 Tagen ohne erneutes Erfuellen fallen Eintraege heraus. Das leere Passwort zaehlt nicht.
 * cnt = Summe der Proben der letzten 365 Tage (je Tag und Zugangsdaten-Paar hoechstens HPS_CAP_DAY).
 */
if(php_sapi_name() !== 'cli') { exit; }
include(__DIR__ . "/../dbconnect.php");
require_once __DIR__ . '/../honeypot/hp_stats_lib.php';
set_time_limit(900);
ini_set('memory_limit', '512M');

const HPW_KEEP_DAYS = 365;     // Fenster der Proben und Frist ohne erneutes Erfuellen der Schwelle
const HPW_CHUNK     = 1000;    // Hashes je Abfrage/INSERT
const HPW_EMPTY     = 'da39a3ee5e6b4b0d3255bfef95601890afd80709'; // SHA-1 des leeren Passworts

$dry = in_array('--dry', $argv, true);
$now = time();
$run = hps_dt($now);

// nicht zweimal gleichzeitig
$lock = fopen(sys_get_temp_dir() . '/ipv64_honeypot_passwords.lock', 'c');
if($lock === false OR !flock($lock, LOCK_EX | LOCK_NB)) { echo "Laeuft schon, Ende\n"; exit(0); }

try {
	[$active, $n] = hps_threshold($pdo, $now);
	// 1. Schwelle erfuellt (30 Tage, verschiedene Accounts je Passwort ueber alle Dienste und Benutzernamen)
	$qual = array_column(hps_all($pdo, "SELECT s.pass_sha1 h, COUNT(DISTINCT k.userid) a FROM hp_sample_contrib k
		JOIN hp_samples_creds s ON s.day = k.day AND s.key_hash = k.key_hash
		WHERE k.kind = 'cred' AND k.day >= :d AND s.pass_sha1 != '' AND s.pass_sha1 != :e GROUP BY s.pass_sha1 HAVING a >= " . (int)$n,
		array('d' => gmdate('Y-m-d', $now - (HPS_DAYS - 1) * 86400), 'e' => HPW_EMPTY)), 'h');
	$qual = array_fill_keys(array_map('strtolower', $qual), true);
	// 2. bisherige Eintraege (noch in der Frist)
	$old = array();
	foreach(hps_all($pdo, "SELECT LOWER(HEX(sha1)) h FROM hp_pw_range WHERE updated >= :d", array('d' => hps_dt($now - HPW_KEEP_DAYS * 86400))) as $r) { $old[$r['h']] = true; }
	$all = array_keys($qual + $old);
	printf("Aktive Accounts (7 Tage): %d, Schwelle: %d Accounts in %d Tagen; Schwelle erfuellt: %d, bisher in der Frist: %d, zusammen: %d\n",
		$active, $n, HPS_DAYS, count($qual), count($old), count($all));

	// 3. Anzahl je Passwort (365 Tage) ueber den Index pass_sha1
	$from = gmdate('Y-m-d', $now - (HPW_KEEP_DAYS - 1) * 86400);
	$rows = array(); $gone = array();
	foreach(array_chunk($all, HPW_CHUNK) as $chunk) {
		$cnt = array();
		foreach(hps_all($pdo, "SELECT pass_sha1 h, SUM(LEAST(`count`, " . HPS_CAP_DAY . ")) c FROM hp_samples_creds WHERE pass_sha1 IN (" . implode(',', array_fill(0, count($chunk), '?')) . ")
			AND day >= ? GROUP BY pass_sha1", array_merge($chunk, array($from))) as $r) { $cnt[strtolower($r['h'])] = (int)$r['c']; }
		foreach($chunk as $h) {
			if(empty($cnt[$h])) { $gone[] = $h; continue; } // keine Proben mehr im Fenster
			$rows[] = array($h, $cnt[$h], isset($qual[$h]) ? 1 : 0);
		}
	}
	printf("Eintraege: %d, ohne Proben im Fenster: %d\n", count($rows), count($gone));
	if($dry) { echo "*** DRY RUN, nichts geschrieben ***\n"; exit(0); }

	// 4. schreiben: Schwelle erfuellt -> Anzahl und updated = jetzt; nur bisher -> nur die Anzahl (updated bleibt)
	foreach(array(1 => 'cnt = VALUES(cnt), updated = VALUES(updated)', 0 => 'cnt = VALUES(cnt)') as $q => $upd) {
		$part = array_values(array_filter($rows, fn($r) => $r[2] === $q));
		foreach(array_chunk($part, HPW_CHUNK) as $chunk) {
			hps_q($pdo, "INSERT INTO hp_pw_range (sha1, cnt, updated) VALUES " . implode(',', array_fill(0, count($chunk), '(UNHEX(?),?,?)')) . " ON DUPLICATE KEY UPDATE $upd",
				array_merge(...array_map(fn($r) => array($r[0], $r[1], $run), $chunk)));
		}
	}
	// 5. aufraeumen: keine Proben mehr im Fenster, Frist ohne erneutes Erfuellen abgelaufen
	$del = 0;
	foreach(array_chunk($gone, HPW_CHUNK) as $chunk) {
		$del += hps_q($pdo, "DELETE FROM hp_pw_range WHERE sha1 IN (" . implode(',', array_fill(0, count($chunk), 'UNHEX(?)')) . ")", $chunk)->rowCount();
	}
	do { $c = hps_q($pdo, "DELETE FROM hp_pw_range WHERE updated < :d LIMIT 10000", array('d' => hps_dt($now - HPW_KEEP_DAYS * 86400)))->rowCount(); $del += $c; } while($c >= 10000);
	printf("hp_pw_range: %d geschrieben, %d entfernt\n", count($rows), $del);
} catch(Throwable $e) {
	fwrite(STDERR, "honeypot_passwords: " . $e->getMessage() . "\n");
	exit(1);
}
echo "Fertig\n";
