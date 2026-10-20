<?php
/**
 * Honeypot64 (H2): Fristen aus Plan Abschnitt 4 durchsetzen (docs/PLAN-NODE64-HONEYPOT64.md im Node64-Repo).
 * Taeglich per Cron, nur auf der Kommandozeile:
 *
 *   php honeypot_cleanup.php            ausfuehren
 *   php honeypot_cleanup.php --dry      nur anzeigen
 *
 * 1. Meldungen mit voller IP (hp_report_sources) aelter als 90 Tage: je Tag nach hp_sources_archive verdichten
 *    (IP auf /24 bzw. /48 gekuerzt, je Netz/Art/Dienst/Port: Ereignisse, IPs, Accounts), Tag in hp_archive_days
 *    vermerken, danach in Bloecken loeschen. Ein Abbruch zaehlt nichts doppelt (verdichtet wird nur einmal je Tag).
 *    ASN und Land fehlen noch (TODO H3: Anreicherung aus den RIR-Daten und einer freien ASN-Datenbank).
 * 2. hp_reports (enthaelt die IP des Sensors) aelter als 90 Tage loeschen.
 * 3. hp_sources_archive und hp_daily aelter als 24 Monate loeschen.
 * Proben (hp_samples_*) bleiben unbegrenzt (keine personenbezogenen Daten).
 */
if(php_sapi_name() !== 'cli') { exit; }
include(__DIR__ . "/../dbconnect.php");

const HPC_FULL_DAYS    = 90;
const HPC_ARCHIVE_DAYS = 730;
const HPC_BATCH        = 10000;

$dry = in_array('--dry', $argv, true);
$pdo->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
$cut = gmdate('Y-m-d', time() - HPC_FULL_DAYS * 86400);
$cutArchive = gmdate('Y-m-d', time() - HPC_ARCHIVE_DAYS * 86400);
echo ($dry ? "NUR ANZEIGEN" : "AUSFUEHREN") . ": volle IPs vor $cut, Archiv/Statistik vor $cutArchive\n";

function hpc_one(string $sql, array $p = array()) { global $pdo; $st = $pdo->prepare($sql); $st->execute($p); return $st->fetchColumn(); }

/** In Bloecken loeschen (kurze Transaktionen, keine langen Sperren). */
function hpc_delete(string $table, string $where, array $p): int {
	global $pdo, $dry;
	if($dry) { return (int)hpc_one("SELECT count(*) FROM $table WHERE $where", $p); }
	$n = 0;
	do {
		$st = $pdo->prepare("DELETE FROM $table WHERE $where LIMIT " . HPC_BATCH);
		$st->execute($p);
		$n += $st->rowCount();
	} while($st->rowCount() === HPC_BATCH);
	return $n;
}

// 1. verdichten (je Tag einmal), dann loeschen
$st = $pdo->prepare("SELECT DISTINCT day FROM hp_report_sources WHERE day < :c ORDER BY day");
$st->execute(array('c' => $cut));
foreach($st->fetchAll(PDO::FETCH_COLUMN) as $day) {
	if(hpc_one("SELECT day FROM hp_archive_days WHERE day = :d", array('d' => $day)) !== false) { continue; }
	echo "verdichte $day\n";
	if($dry) { continue; }
	$pdo->beginTransaction();
	// /24: die ersten 3 Bytes, /48: die ersten 6 Bytes, Rest genullt
	$pdo->prepare("INSERT INTO hp_sources_archive (day, net_bin, family, kind, service, port, events, ips, accounts)
		SELECT day, IF(LENGTH(ip_bin) = 4, CONCAT(SUBSTRING(ip_bin, 1, 3), UNHEX('00')), CONCAT(SUBSTRING(ip_bin, 1, 6), UNHEX('00000000000000000000'))) net,
			IF(LENGTH(ip_bin) = 4, 4, 6), kind, service, port, SUM(`count`), COUNT(DISTINCT ip_bin), COUNT(DISTINCT userid)
		FROM hp_report_sources WHERE day = :d GROUP BY day, net, kind, service, port
		ON DUPLICATE KEY UPDATE events = VALUES(events), ips = VALUES(ips), accounts = VALUES(accounts)")->execute(array('d' => $day));
	$pdo->prepare("INSERT INTO hp_archive_days (day, archived_at) VALUES (:d, UTC_TIMESTAMP())")->execute(array('d' => $day));
	$pdo->commit();
}
echo "hp_report_sources: " . hpc_delete('hp_report_sources', "day < :c AND day IN (SELECT day FROM hp_archive_days)", array('c' => $cut)) . " Zeile(n)\n";

// 2. Meldungen (IP des Sensors)
echo "hp_reports: " . hpc_delete('hp_reports', "day < :c", array('c' => $cut)) . " Zeile(n)\n";

// 3. nach 24 Monaten
echo "hp_sources_archive: " . hpc_delete('hp_sources_archive', "day < :c", array('c' => $cutArchive)) . " Zeile(n)\n";
echo "hp_daily: " . hpc_delete('hp_daily', "day < :c", array('c' => $cutArchive)) . " Zeile(n)\n";
echo "hp_archive_days: " . hpc_delete('hp_archive_days', "day < :c", array('c' => $cutArchive)) . " Zeile(n)\n";
