<?php
/**
 * Altes CDN (srv01-srv06) abschalten, T8 der Planung (docs/CDN64-ONLINE.md im Node64-Repo).
 * Je Domain im alten CDN: CDN-Eintraege (cdn_tmp 1/2) loeschen, die deaktivierten Originale wieder aktivieren,
 * DNS neu schreiben - erst danach dell = 1, damit cdn_bot.php die Server abraeumt. (Der Loeschlauf des cdn_bot
 * loescht alle Eintraege mit dem CDN-Token, also auch die Originale - darum hier vorher zuruecksetzen.)
 * Nur auf der Kommandozeile, die alten Server muessen dabei noch laufen (cdn_bot raeumt nur Server mit online = 1 ab).
 *
 *   php cdn_alt_abschalten.php                   nur anzeigen, was passieren wuerde
 *   php cdn_alt_abschalten.php --domain=1234     nur diese Domain (subdomains.id), zum Ausprobieren
 *   php cdn_alt_abschalten.php --run             ausfuehren
 */
if(php_sapi_name() !== 'cli') { exit; }
include(__DIR__ . "/../dbconnect.php");

$run = in_array('--run', $argv, true);
$only = 0;
foreach($argv as $a) { if(str_starts_with($a, '--domain=')) { $only = (int)substr($a, 9); } }

$statement = $pdo->prepare("SELECT * FROM cdn_domains WHERE dell = '0'" . ($only ? " AND domainid = :d" : "") . " ORDER BY id");
$statement->execute($only ? array('d' => $only) : array());
$cdn_domains = $statement->fetchAll();
echo ($run ? "AUSFUEHREN" : "NUR ANZEIGEN (--run zum Ausfuehren)") . ": " . count($cdn_domains) . " Domain(s) im alten CDN\n";

foreach($cdn_domains as $cdn)
{
	$statement = $pdo->prepare("SELECT id,praefix,type,ttl,cdn_tmp FROM subdomain_records WHERE BINARY cdn_token = :t");
	$statement->execute(array('t' => $cdn["token"]));
	$recs = $statement->fetchAll();
	$orig = 0; $tmp = 0; $rrsets = array();
	foreach($recs as $r) {
		if((int)$r["cdn_tmp"] === 0) { $orig++; } else { $tmp++; }
		$k = $r["praefix"] . "|" . $r["type"];
		// TTL des Originals, sonst Standard
		if(!isset($rrsets[$k]) OR (int)$r["cdn_tmp"] === 0) { $rrsets[$k] = array($r["praefix"], $r["type"], (int)$r["cdn_tmp"] === 0 ? (int)$r["ttl"] : 60); }
	}
	echo "domain $cdn[domainid] (user $cdn[userid]): $orig Original(e) zurueck, $tmp CDN-Eintrag/Eintraege weg, " . count($rrsets) . " DNS-Satz/Saetze neu\n";
	if(!$run) { continue; }

	$statement = $pdo->prepare("DELETE FROM subdomain_records WHERE BINARY cdn_token = :t AND cdn_tmp != '0'");
	$statement->execute(array('t' => $cdn["token"]));
	$statement = $pdo->prepare("UPDATE subdomain_records SET deactivated = '0', cdn_status = '0', cdn_token = '0', cdn_not = '0' WHERE BINARY cdn_token = :t AND cdn_tmp = '0'");
	$statement->execute(array('t' => $cdn["token"]));
	foreach($rrsets as $s) { do_zone_update($pdo, $cdn["userid"], $cdn["domainid"], $s[1], $s[2], $s[0]); }

	$statement = $pdo->prepare("UPDATE cdn_domains SET dell = '1' WHERE id = :id");
	$statement->execute(array('id' => $cdn["id"]));
	add_log($pdo, $cdn["userid"], $cdn["domainid"], "CDN", "Altes CDN abgeschaltet, DNS zeigt wieder auf die eigenen Eintraege.");
}
echo "fertig\n";
