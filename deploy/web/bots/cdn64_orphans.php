<?php
/**
 * CDN64: verwaiste Tunnel aufraeumen (Node64-Container geloescht, ohne vorher abzumelden). Stuendlich ueber
 * honeypot_cron.php (Job "cdn64old"), nur Kommandozeile:
 *
 *   php cdn64_orphans.php          ausfuehren
 *   php cdn64_orphans.php --dry    nur anzeigen, nichts aendern
 *
 * Ein Tunnel, der seit 14 Tagen nicht verbunden war (last_seen; nie verbunden: seit dem Anlegen), wird mit allem
 * entfernt: DNS seiner Namen zurueck auf die urspruenglichen Eintraege, die Namen mit Zuordnung, Ziel, Liste,
 * Portmapper und Zertifikat, zuletzt der Tunnel samt Token. Die CDN64-Server holen ihre Konfiguration alle 10 s und
 * lassen die Namen danach fallen. Keine Benachrichtigung; ab 48 Stunden zeigt die Seite cdn64 einen Hinweis mit Datum.
 * Ein Name, der noch an einem anderen (verbundenen) Tunnel haengt, bleibt.
 *
 * Sicherung: nur, wenn sich gerade ein CDN64-Server meldet und in den letzten 15 Minuten irgendein Tunnel verbunden
 * war - sonst stammen alte last_seen eher von einem Ausfall bei ipv64 bzw. den Servern als von verwaisten Nodes.
 */
if(php_sapi_name() !== 'cli') { exit; }
include(__DIR__ . "/../dbconnect.php");

const C64X_AFTER   = 14; // Tage ohne Verbindung
const C64X_CDN_TMP = 3;  // Markierung der Server-Eintraege in subdomain_records (wie C64O_CDN_TMP in api_v2_cdn64o.php)
const C64X_TTL     = 10; // wie C64O_TTL

$dry = in_array('--dry', $argv, true);
$l = $pdo->query("SELECT GET_LOCK('cdn64_orphans', 0) l")->fetch(PDO::FETCH_ASSOC);
if((int)($l['l'] ?? 0) !== 1) { echo "laeuft bereits\n"; exit(0); }
$q = function(string $sql, array $a = array()) use ($pdo): PDOStatement { $st = $pdo->prepare($sql); $st->execute($a); return $st; };

$edge = (int)$q("SELECT COUNT(*) FROM cdn64o_edges WHERE disabled = 0 AND last_seen >= NOW() - INTERVAL 60 SECOND")->fetchColumn();
$live = (int)$q("SELECT COUNT(*) FROM cdn64o_tunnels WHERE last_seen >= NOW() - INTERVAL 15 MINUTE")->fetchColumn();
if($edge === 0 OR $live === 0) { echo "kein CDN64-Server bzw. kein verbundener Tunnel gerade - nichts geprueft\n"; exit(0); }

// wie c64o_dns_off: Server-Eintraege loeschen, Originale wieder aktivieren, an PowerDNS
$dnsOff = function(array $h) use ($q, $pdo): void {
	foreach($q("SELECT record_id, role FROM cdn64o_records WHERE host_id = :h", array('h' => $h['id']))->fetchAll(PDO::FETCH_ASSOC) as $r) {
		if($r['role'] === 'edge') {
			$q("DELETE FROM subdomain_records WHERE id = :i AND cdn_tmp = :m", array('i' => $r['record_id'], 'm' => C64X_CDN_TMP));
		} else {
			$q("UPDATE subdomain_records set deactivated = 0 WHERE id = :i", array('i' => $r['record_id']));
		}
	}
	$q("DELETE FROM cdn64o_records WHERE host_id = :h", array('h' => $h['id']));
	foreach(array('A', 'AAAA') as $t) {
		ob_start();
		try { do_zone_update($pdo, (int)$h['userid'], (int)$h['subdomain_id'], $t, (string)C64X_TTL, $h['praefix']); }
		catch(Throwable $e) { echo "  DNS " . $h['fqdn'] . " $t: " . $e->getMessage() . "\n"; }
		finally { ob_end_clean(); }
	}
};
// wie c64o_host_purge: alles eines Namens
$purge = function(array $h) use ($q): void {
	foreach(array('cdn64o_host_tunnels', 'cdn64o_targets', 'cdn64o_acl', 'cdn64o_mappings') as $tab) { $q("DELETE FROM $tab WHERE host_id = :h", array('h' => $h['id'])); }
	$q("DELETE FROM cdn64o_certs WHERE fqdn = :f", array('f' => $h['fqdn']));
	$q("DELETE FROM cdn64o_hosts WHERE id = :h", array('h' => $h['id']));
	$q("INSERT INTO cdn64o_events (host_id, userid, kind, message) VALUES (:h, :u, 'disabled', :m)",
		array('h' => $h['id'], 'u' => $h['userid'], 'm' => 'node not connected for ' . C64X_AFTER . ' days: removed'));
};

$tunnels = $q("SELECT * FROM cdn64o_tunnels WHERE COALESCE(last_seen, created_at) < NOW() - INTERVAL " . C64X_AFTER . " DAY")->fetchAll(PDO::FETCH_ASSOC);
$names = 0;
foreach($tunnels as $t) {
	$hosts = $q("SELECT h.* FROM cdn64o_hosts h JOIN cdn64o_host_tunnels ht ON ht.host_id = h.id WHERE ht.tunnel_id = :t", array('t' => $t['id']))->fetchAll(PDO::FETCH_ASSOC);
	echo "Tunnel " . $t['id'] . " (User " . $t['userid'] . ", zuletzt " . ($t['last_seen'] ?? 'nie, angelegt ' . $t['created_at']) . "): " . count($hosts) . " Name(n)\n";
	if($dry) { foreach($hosts as $h) { echo "  " . $h['fqdn'] . "\n"; } continue; }
	$gone = array();
	foreach($hosts as $h) {
		$q("DELETE FROM cdn64o_host_tunnels WHERE host_id = :h AND tunnel_id = :t", array('h' => $h['id'], 't' => $t['id']));
		if($q("SELECT host_id FROM cdn64o_host_tunnels WHERE host_id = :h LIMIT 1", array('h' => $h['id']))->fetch() !== false) { continue; } // haengt noch an einem anderen Tunnel
		$dnsOff($h);
		$purge($h);
		$gone[] = $h['fqdn'];
	}
	$q("DELETE FROM cdn64o_tunnels WHERE id = :i", array('i' => $t['id']));
	$names += count($gone);
	if(function_exists('add_log')) {
		add_log($pdo, $t['userid'], "0", "CDN64 online", "Tunnel " . $t['id'] . " was not connected for " . C64X_AFTER . " days and was removed" . ($gone ? " with: " . implode(', ', $gone) : "") . ".");
	}
}
echo count($tunnels) . " Tunnel" . ($dry ? " (nur angezeigt)" : " entfernt, $names Name(n)") . "\n";
