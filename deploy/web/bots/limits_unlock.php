<?php
/**
 * Limits nach einer Klassenaenderung freigeben, auch wenn die Klasse ausserhalb von account.php geaendert wurde
 * (z. B. von Hand in der Datenbank). Alle 5 Minuten ueber honeypot_cron.php (Job "unlock"), nur Kommandozeile:
 *
 *   php limits_unlock.php            ausfuehren
 *
 * Kandidaten: Accounts mit wegen Traffic gesperrten CDN64-Namen oder gedrosseltem Cloud Router. Die Pruefung selbst
 * steht in ../limits_unlock_lib.php (gleich wie nach dem Upgrade in account.php).
 */
if(php_sapi_name() !== 'cli') { exit; }
include(__DIR__ . "/../dbconnect.php");
require_once __DIR__ . '/../limits_unlock_lib.php';

$l = $pdo->query("SELECT GET_LOCK('limits_unlock', 0) l")->fetch(PDO::FETCH_ASSOC);
if((int)($l['l'] ?? 0) !== 1) { echo "laeuft bereits\n"; exit(0); }
$ids = array();
foreach(array("SELECT DISTINCT userid id FROM cdn64o_hosts WHERE status = 'blocked' AND blocked_reason = 'traffic'",
	"SELECT id FROM users WHERE vpn_limit_reached = 1") as $sql) {
	try { foreach($pdo->query($sql)->fetchAll(PDO::FETCH_ASSOC) as $r) { $ids[(int)$r['id']] = true; } } catch(Throwable $e) { echo "Abfrage: " . $e->getMessage() . "\n"; }
}
$freed = 0;
foreach(array_keys($ids) as $u) {
	$r = ipv64_limits_unlock($pdo, $u);
	if(!empty($r['cdn64']) OR isset($r['vpn'])) { $freed++; echo "User $u: " . json_encode($r) . "\n"; }
}
echo count($ids) . " geprueft, $freed freigegeben\n";
