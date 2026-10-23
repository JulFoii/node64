<?php
/**
 * IPv64.net – Wochenbericht verschicken. Stuendlich ueber honeypot_cron.php (Job "weekly"), nur Kommandozeile:
 *
 *   php weekly_report.php                       faellige Berichte dieser Woche senden (6–21 Uhr)
 *   php weekly_report.php --dry                 nur zeigen, wer jetzt dran waere
 *   php weekly_report.php --test=<id> --to=<mail>   Bericht von Account <id> sofort an <mail> (Test, ohne Protokoll)
 *   php weekly_report.php --stats               Verteilung ueber die Woche und Stand dieser Woche
 *
 * Verteilung: jeder Account hat einen festen Termin (wr_slot: Wochentag und Stunde 6–21 Uhr, gleichmaessig verteilt).
 * Ein Lauf schickt allen mit eingeschaltetem Bericht, deren Termin in dieser Woche erreicht ist und die noch keinen
 * Eintrag in weekly_report_log haben – hoechstens WR_RUN_MAX je Lauf (Rest im naechsten Lauf). Accounts ohne Dienste
 * bekommen keine Mail (Eintrag ok=2), damit niemand leere Berichte erhaelt. Fehlgeschlagene Mails werden in den
 * naechsten Laeufen bis zu dreimal wiederholt; nach 10 Fehlern am Stueck bricht ein Lauf ab (Mailserver gestoert).
 */
if (php_sapi_name() !== 'cli') { exit; }
include(__DIR__ . '/../dbconnect.php');
if (!class_exists('PHPMailer\PHPMailer\PHPMailer') && is_file(__DIR__ . '/vendor/autoload.php')) { require __DIR__ . '/vendor/autoload.php'; }
require_once __DIR__ . '/../weekly_report_lib.php';

const WR_RUN_MAX = 400;

$opt = getopt('', array('dry', 'test:', 'to:', 'stats'));
$now = time();
$week = wr_week($now);

if (isset($opt['test'])) {
	$d = wr_collect($pdo, (int)$opt['test'], $now);
	if ($d === null) { fwrite(STDERR, "Account unbekannt oder gesperrt\n"); exit(1); }
	$err = wr_send($pdo, $d, (string)($opt['to'] ?? ''));
	echo $err === '' ? "gesendet\n" : "Fehler: $err\n";
	if ($d['errors']) { echo "Hinweise: " . implode('; ', $d['errors']) . "\n"; }
	exit($err === '' ? 0 : 1);
}

if (isset($opt['stats'])) {
	$per = array_fill(0, 7, 0); $n = 0;
	foreach ($pdo->query("SELECT id FROM users WHERE weekly_report = 1 AND account_status = '1'")->fetchAll(PDO::FETCH_COLUMN) as $id) { $per[intdiv(wr_slot((int)$id), WR_HOURS)]++; $n++; }
	echo "eingeschaltet: $n\nje Tag (Mo–So): " . implode(' ', $per) . "\n";
	$st = $pdo->prepare("SELECT ok, COUNT(*) FROM weekly_report_log WHERE week = :w GROUP BY ok"); $st->execute(array('w' => $week));
	foreach ($st->fetchAll(PDO::FETCH_NUM) as $r) { echo "Woche $week, " . array('Fehler', 'gesendet', 'ohne Dienste')[(int)$r[0]] . ": $r[1]\n"; }
	exit(0);
}

$slotNow = wr_slot_now($now);
if ($slotNow === null) { echo "ausserhalb der Versandzeit\n"; exit(0); }
if ((int)($pdo->query("SELECT GET_LOCK('weekly_report', 0)")->fetchColumn()) !== 1) { echo "laeuft bereits\n"; exit(0); }

$st = $pdo->prepare("SELECT u.id, u.email FROM users u LEFT JOIN weekly_report_log l ON l.userid = u.id AND l.week = :w
	WHERE u.weekly_report = 1 AND u.account_status = '1' AND u.email <> '' AND (l.userid IS NULL OR (l.ok = 0 AND l.tries < 3))");
$st->execute(array('w' => $week));
$due = array();
foreach ($st->fetchAll(PDO::FETCH_ASSOC) as $r) {
	$s = wr_slot((int)$r['id']);
	if ($s <= $slotNow) { $due[] = array($s, (int)$r['id'], (string)$r['email']); }
}
usort($due, function($a, $b) { return $a[0] <=> $b[0] ?: $a[1] <=> $b[1]; });
$due = array_slice($due, 0, WR_RUN_MAX);
if (isset($opt['dry'])) { echo "Woche $week, Termin jetzt $slotNow: " . count($due) . " faellig\n"; foreach ($due as $x) { echo "  $x[1] (Termin $x[0])\n"; } exit(0); }

$log = $pdo->prepare("INSERT INTO weekly_report_log (userid, week, sent_at, ok, error, tries) VALUES (:u, :w, NOW(), :ok, :e, 1)
	ON DUPLICATE KEY UPDATE sent_at = NOW(), ok = VALUES(ok), error = VALUES(error), tries = tries + 1");
$sent = 0; $skipped = 0; $failed = 0; $streak = 0;
foreach ($due as $x) {
	try {
		$d = wr_collect($pdo, $x[1], $now);
		if ($d === null || !wr_has_content($d)) {
			$log->execute(array('u' => $x[1], 'w' => $week, 'ok' => 2, 'e' => ''));
			$skipped++;
			continue;
		}
		$err = wr_send($pdo, $d, $x[2]);
	} catch (Throwable $e) { $err = $e->getMessage(); }
	$log->execute(array('u' => $x[1], 'w' => $week, 'ok' => $err === '' ? 1 : 0, 'e' => mb_substr($err, 0, 255)));
	if ($err === '') { $sent++; $streak = 0; } else { $failed++; $streak++; }
	if ($streak >= 10) { echo "10 Fehler am Stueck, Abbruch: $err\n"; break; }
	usleep(300000); // Mailserver schonen
}
echo "Woche $week: $sent gesendet, $skipped ohne Dienste, $failed Fehler\n";
