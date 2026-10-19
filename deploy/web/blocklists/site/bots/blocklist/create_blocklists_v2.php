<?php
// IPv64.net Blocklisten-Generator v2 (Ersatz fuer create_blocklists.php)
//
// Liest die importierten Quelltabellen (blocklisten.db_name) und bl_countries_ips
// und schreibt alle Dateien unter blocklists/ neu. Dateinamen bleiben identisch,
// bestehende Links funktionieren weiter.
//
// Was gegenueber v1 anders ist:
//   - jede Zeile wird in ein sauberes Netz normalisiert (Hostbits weg, /32 bzw. /128 fuer Einzeladressen)
//   - Duplikate und enthaltene Netze werden in JEDER Datei entfernt (auch v6, auch "all")
//   - nicht routbare Bereiche (privat, CGNAT, Loopback, Link-Local, Multicast, Dokumentation) fliegen raus
//   - numerisch sortiert, damit Diffs und Vergleiche stabil sind
//   - MikroTik: IPv6 bekommt "/ipv6 firewall address-list", und am Anfang steht ein remove,
//     damit ein erneuter Import keine Duplikate erzeugt
//   - Dateien werden erst in eine Temp-Datei geschrieben und dann umbenannt (kein halber Download)
//   - last_updated wird nur gesetzt, wenn wirklich Dateien geschrieben wurden
//
// Aufruf:  php create_blocklists_v2.php              -> schreibt nach ../../blocklists/
//          php create_blocklists_v2.php --out=/tmp/x  -> schreibt zum Vergleichen nach /tmp/x (keine DB-Updates)
//          php create_blocklists_v2.php --dry         -> nur Statistik, schreibt nichts
include("/var/www/clients/client1/web58/web/dbconnect.php");
set_time_limit(900);
ini_set('memory_limit', '1024M');

$OUT = realpath(__DIR__."/../../blocklists");
$dry = false; $extern = false;
foreach($argv as $a) {
	if($a === '--dry') { $dry = true; }
	if(str_starts_with($a, '--out=')) { $OUT = rtrim(substr($a, 6), '/'); $extern = true; @mkdir($OUT, 0755, true); @mkdir($OUT."/countries", 0755, true); @mkdir($OUT."/user", 0755, true); }
}
if($OUT === false OR !is_dir($OUT)) { die("Ausgabeverzeichnis nicht gefunden\n"); }
echo ($dry ? "*** DRY RUN ***\n" : "Ausgabe: $OUT\n");

// ---------------------------------------------------------------
// Netz-Helfer (ohne externe Bibliothek, IPv4 und IPv6 ueber Binaerstrings)
// ---------------------------------------------------------------

/** "1.2.3.4", "1.2.3.0/24", "2001:db8::1", "2001:db8::/32" -> ['v'=>4|6,'bin'=>Netzadresse binaer,'len'=>Praefix] oder null */
function net_parse(string $s): ?array
{
	$s = trim($s);
	if($s === '') { return null; }
	$len = null;
	if(str_contains($s, '/')) { [$s, $l] = explode('/', $s, 2); if(!ctype_digit($l)) { return null; } $len = (int)$l; }
	$s = trim($s, " \t[]");
	if(filter_var($s, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4)) { $v = 4; $bits = 32; }
	elseif(filter_var($s, FILTER_VALIDATE_IP, FILTER_FLAG_IPV6)) { $v = 6; $bits = 128; }
	else { return null; }
	if($len === null) { $len = $bits; }
	if($len < 0 OR $len > $bits) { return null; }
	$bin = inet_pton($s);
	if($bin === false) { return null; }
	// Hostbits loeschen
	$bin = $bin & net_mask($len, strlen($bin));
	return ['v' => $v, 'bin' => $bin, 'len' => $len];
}

/** Maske als Binaerstring */
function net_mask(int $len, int $bytes): string
{
	$m = '';
	for($i = 0; $i < $bytes; $i++) {
		$b = max(0, min(8, $len - $i * 8));
		$m .= chr($b === 0 ? 0 : (0xFF << (8 - $b)) & 0xFF);
	}
	return $m;
}

/** Liegt $b innerhalb von $a (oder ist gleich)? */
function net_contains(array $a, array $b): bool
{
	if($a['v'] !== $b['v'] OR $b['len'] < $a['len']) { return false; }
	$m = net_mask($a['len'], strlen($a['bin']));
	return ($b['bin'] & $m) === $a['bin'];
}

function net_str(array $n): string
{
	return inet_ntop($n['bin']).'/'.$n['len'];
}

/** Sortieren (Version, Adresse, Praefix), Duplikate und enthaltene Netze entfernen */
function net_merge(array $nets): array
{
	usort($nets, function($a, $b) {
		return ($a['v'] <=> $b['v']) ?: (strcmp($a['bin'], $b['bin']) ?: ($a['len'] <=> $b['len']));
	});
	$out = []; $cur = null;
	foreach($nets as $n) {
		if($cur !== null AND net_contains($cur, $n)) { continue; }   // Duplikat oder enthalten
		$out[] = $n; $cur = $n;
	}
	return $out;
}

/** Nicht routbare Bereiche: Eintraege, die darin liegen oder sie umfassen, werden verworfen */
$BOGONS = array_map('net_parse', [
	'0.0.0.0/8','10.0.0.0/8','100.64.0.0/10','127.0.0.0/8','169.254.0.0/16','172.16.0.0/12',
	'192.0.0.0/24','192.0.2.0/24','192.168.0.0/16','198.18.0.0/15','198.51.100.0/24','203.0.113.0/24',
	'224.0.0.0/4','240.0.0.0/4',
	'::/128','::1/128','::ffff:0:0/96','64:ff9b::/96','100::/64','2001:db8::/32','fc00::/7','fe80::/10','ff00::/8',
]);
function net_is_bogon(array $n): bool
{
	global $BOGONS;
	foreach($BOGONS as $b) { if(net_contains($b, $n) OR net_contains($n, $b)) { return true; } }
	return false;
}

/** Liste von Strings -> bereinigte, sortierte Netze. Gibt [nets, verworfen, bogons] zurueck. */
function net_clean(array $lines): array
{
	$nets = []; $bad = 0; $bog = 0;
	foreach($lines as $l) {
		$n = net_parse((string)$l);
		if($n === null) { $bad++; continue; }
		if(net_is_bogon($n)) { $bog++; continue; }
		$nets[] = $n;
	}
	return [net_merge($nets), $bad, $bog];
}

// ---------------------------------------------------------------
// Dateien schreiben (atomar)
// ---------------------------------------------------------------
function write_atomic(string $path, string $content): void
{
	global $dry;
	if($dry) { return; }
	$tmp = $path.".tmp";
	file_put_contents($tmp, $content);
	chmod($tmp, 0644);
	rename($tmp, $path);
}

function write_raw(string $path, array $nets): void
{
	$s = '';
	foreach($nets as $n) { $s .= net_str($n)."\n"; }
	write_atomic($path, $s);
}

function write_mikrotik(string $path, array $nets, int $v, string $listname = "IPv64-Blocklist"): void
{
	$pfad = ($v === 6) ? "/ipv6 firewall address-list" : "/ip firewall address-list";
	$s  = "# IPv64.net Blocklist - ".date("Y-m-d H:i")." UTC - https://ipv64.net/v64_blocklists\n";
	$s .= "$pfad\n";
	$s .= "remove [find list=$listname comment=\"IPv64 Blocklist\"]\n";
	foreach($nets as $n) { $s .= "add list=$listname address=".net_str($n)." comment=\"IPv64 Blocklist\"\n"; }
	write_atomic($path, $s);
}

function split46(array $nets): array
{
	$v4 = []; $v6 = [];
	foreach($nets as $n) { if($n['v'] === 4) { $v4[] = $n; } else { $v6[] = $n; } }
	return [$v4, $v6];
}

// ---------------------------------------------------------------
// 1. Einzelne Quelllisten
// ---------------------------------------------------------------
$alle = [];
$statement = $pdo->prepare("SELECT * FROM blocklisten WHERE disabled = 0");
$statement->execute();
foreach($statement->fetchAll(PDO::FETCH_ASSOC) as $bl)
{
	if(!preg_match('/^[a-z0-9_]+$/', $bl["db_name"]) OR !preg_match('/^[a-z0-9_]+$/', $bl["file_name"])) { echo "SKIP ".$bl["name"].": unsauberer Tabellen-/Dateiname\n"; continue; }
	$rows = $pdo->query("SELECT ip FROM `".$bl["db_name"]."`")->fetchAll(PDO::FETCH_COLUMN);
	if(count($rows) === 0) { echo "SKIP ".$bl["name"].": Quelltabelle leer, Dateien bleiben wie sie sind\n"; continue; }
	[$nets, $bad, $bog] = net_clean($rows);
	[$v4, $v6] = split46($nets);
	foreach($nets as $n) { $alle[] = $n; }
	printf("%-22s Quelle %6d -> %6d Netze (v4 %6d, v6 %4d) | ungueltig %d, nicht routbar %d\n", $bl["name"], count($rows), count($nets), count($v4), count($v6), $bad, $bog);

	$f = $bl["file_name"];
	write_raw("$OUT/ipv64_blocklist_$f.txt", $nets);
	write_raw("$OUT/ipv64_blocklist_v4_$f.txt", $v4);
	write_raw("$OUT/ipv64_blocklist_v6_$f.txt", $v6);
	write_mikrotik("$OUT/v64_mikrotik_v4_$f.rsc", $v4, 4);
	write_mikrotik("$OUT/v64_mikrotik_v6_$f.rsc", $v6, 6);
	if(!$dry AND !$extern) {
		$st = $pdo->prepare("UPDATE blocklisten set ips = :ips WHERE id = :id");
		$st->execute(['ips' => count($nets), 'id' => $bl["id"]]);
	}
}

// ---------------------------------------------------------------
// 2. Gesamtliste
// ---------------------------------------------------------------
$alle = net_merge($alle);
[$v4, $v6] = split46($alle);
printf("%-22s %6d Netze (v4 %6d, v6 %4d)\n", "ALL", count($alle), count($v4), count($v6));
write_raw("$OUT/ipv64_blocklist_all.txt", $alle);
write_raw("$OUT/ipv64_blocklist_v4_all.txt", $v4);
write_raw("$OUT/ipv64_blocklist_v6_all.txt", $v6);
write_mikrotik("$OUT/v64_mikrotik_v4_all.rsc", $v4, 4);
write_mikrotik("$OUT/v64_mikrotik_v6_all.rsc", $v6, 6);

// ---------------------------------------------------------------
// 3. Laender und Regionen
// ---------------------------------------------------------------
$regionen = [
	"europe"        => ['AL','AD','AT','BY','BE','BA','BG','HR','CY','CZ','DK','EE','FI','FR','DE','GR','HU','IS','IE','IT','LV','LI','LT','LU','MK','MT','MD','MC','ME','NL','NO','PL','PT','RO','RU','SM','RS','SK','SI','ES','SE','CH','UA','GB','VA'],
	"africa"        => ['DZ','AO','BJ','BW','BF','BI','CM','CV','CF','TD','KM','CG','CD','DJ','EG','GQ','ER','ET','GA','GM','GH','GN','GW','CI','KE','LS','LR','LY','MG','MW','ML','MR','MU','MA','MZ','NA','NE','NG','RW','ST','SN','SC','SL','SO','ZA','SS','SD','SZ','TZ','TG','TN','UG','ZM','ZW'],
	"asia"          => ['AF','AM','AZ','BH','BD','BT','BN','KH','CN','GE','IN','ID','IR','IQ','IL','JP','JO','KZ','KW','KG','LA','LB','MY','MV','MN','MM','NP','KP','OM','PK','PS','PH','QA','SA','SG','KR','LK','SY','TW','TJ','TH','TL','TR','TM','AE','UZ','VN','YE','HK','MO'],
	"north_america" => ['AG','BS','BB','BZ','CA','CR','CU','DM','DO','SV','GD','GT','HT','HN','JM','MX','NI','PA','KN','LC','VC','TT','US'],
];
$region_nets = array_fill_keys(array_keys($regionen), []);

$st = $pdo->prepare("SELECT ip FROM bl_countries_ips WHERE country = :c");
$laender = $pdo->query("SELECT id, country, file_name FROM blocklisten_countries ORDER BY country")->fetchAll(PDO::FETCH_ASSOC);
$geschrieben = 0;
foreach($laender as $land)
{
	if(!preg_match('/^[A-Za-z0-9_]+$/', $land["file_name"])) { continue; }
	$st->execute(['c' => $land["country"]]);
	$rows = $st->fetchAll(PDO::FETCH_COLUMN);
	if(count($rows) === 0) { continue; }
	[$nets, $bad, $bog] = net_clean($rows);
	[$v4, $v6] = split46($nets);
	$f = $land["file_name"];
	write_raw("$OUT/countries/ipv64_blocklist_$f.txt", $nets);
	write_raw("$OUT/countries/ipv64_blocklist_v4_$f.txt", $v4);
	write_raw("$OUT/countries/ipv64_blocklist_v6_$f.txt", $v6);
	$geschrieben++;
	foreach($regionen as $r => $cc) { if(in_array(strtoupper($land["country"]), $cc, true)) { foreach($nets as $n) { $region_nets[$r][] = $n; } } }
	if(!$dry AND !$extern) {
		$up = $pdo->prepare("UPDATE blocklisten_countries set ips = :ips, last_updated = NOW() WHERE id = :id");
		$up->execute(['ips' => count($nets), 'id' => $land["id"]]);
	}
}
echo "Laender: $geschrieben Dateisaetze geschrieben\n";

foreach($region_nets as $r => $nets)
{
	$nets = net_merge($nets);
	[$v4, $v6] = split46($nets);
	printf("%-22s %6d Netze (v4 %6d, v6 %4d)\n", "Region $r", count($nets), count($v4), count($v6));
	write_raw("$OUT/countries/ipv64_blocklist_$r.txt", $nets);
	write_raw("$OUT/countries/ipv64_blocklist_v4_$r.txt", $v4);
	write_raw("$OUT/countries/ipv64_blocklist_v6_$r.txt", $v6);
}

echo "Fertig".($dry ? " (nichts geschrieben)" : "")."\n";
?>
