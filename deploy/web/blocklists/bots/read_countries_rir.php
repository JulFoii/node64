<?php
// IPv64.net: Laender-Blocklisten aus den offiziellen Zuteilungsdaten der fuenf Registrierungsstellen (RIR)
// (ARIN, RIPE NCC, APNIC, LACNIC, AFRINIC; "delegated-extended", taeglich aktualisiert, frei nutzbar).
// Ersetzt den einmaligen Import aus global.json (Stand 2024). Fuellt bl_countries_ips neu; die Dateien schreibt
// danach wie bisher create_blocklists_v2.php.
//
// Aufruf:  php read_countries_rir.php         -> laedt, prueft und ersetzt bl_countries_ips
//          php read_countries_rir.php --dry   -> nur laden und Statistik, keine Datenbank
// Cron (taeglich, vor create_blocklists_v2.php), z. B.:  20 3 * * * php .../read_countries_rir.php
set_time_limit(1800);
ini_set('memory_limit', '1024M');
$dry = in_array('--dry', $argv ?? [], true);
if(!$dry) { include("/var/www/clients/client1/web58/web/dbconnect.php"); }

$quellen = [
	'arin'    => 'https://ftp.arin.net/pub/stats/arin/delegated-arin-extended-latest',
	'ripencc' => 'https://ftp.ripe.net/pub/stats/ripencc/delegated-ripencc-extended-latest',
	'apnic'   => 'https://ftp.apnic.net/stats/apnic/delegated-apnic-extended-latest',
	'lacnic'  => 'https://ftp.lacnic.net/pub/stats/lacnic/delegated-lacnic-extended-latest',
	'afrinic' => 'https://ftp.afrinic.net/pub/stats/afrinic/delegated-afrinic-extended-latest',
];

/** IPv4-Bereich (Start, Anzahl Adressen) in CIDR-Netze zerlegen (RIR-Bereiche sind nicht immer Zweierpotenzen). */
function v4_cidrs(string $start, int $count): array
{
	$out = [];
	$ip = ip2long($start);
	if($ip === false || $count <= 0) { return $out; }
	$ip = $ip & 0xFFFFFFFF;
	while($count > 0) {
		$max = 32;
		while($max > 0) { // groesstes Netz, das an $ip ausgerichtet ist und in den Rest passt
			$size = 1 << (32 - ($max - 1));
			if(($ip % $size) !== 0 || $size > $count) { break; }
			$max--;
		}
		$out[] = long2ip($ip) . '/' . $max;
		$n = 1 << (32 - $max);
		$ip += $n;
		$count -= $n;
	}
	return $out;
}

$netze = []; // Land -> [ [ip, typ], ... ]
$fehler = [];
foreach($quellen as $rir => $url) {
	$ctx = stream_context_create(['http' => ['timeout' => 120, 'user_agent' => 'ipv64.net blocklists']]);
	$text = @file_get_contents($url, false, $ctx);
	if($text === false || strlen($text) < 100000) { $fehler[] = $rir; echo "$rir: Download fehlgeschlagen\n"; continue; }
	$n = 0;
	foreach(explode("\n", $text) as $line) {
		if($line === '' || $line[0] === '#') { continue; }
		$f = explode('|', $line);
		// registry|cc|type|start|value|date|status[|opaque-id]; Zusammenfassungszeilen haben "*" als cc
		if(count($f) < 7 || ($f[2] !== 'ipv4' && $f[2] !== 'ipv6')) { continue; }
		$cc = strtoupper($f[1]);
		if(!preg_match('/^[A-Z]{2}$/', $cc) || ($f[6] !== 'allocated' && $f[6] !== 'assigned')) { continue; }
		if($f[2] === 'ipv4') {
			foreach(v4_cidrs($f[3], (int)$f[4]) as $c) { $netze[$cc][] = [$c, '4']; $n++; }
		} elseif(filter_var($f[3], FILTER_VALIDATE_IP, FILTER_FLAG_IPV6) && ctype_digit($f[4]) && (int)$f[4] <= 128) {
			$netze[$cc][] = [$f[3] . '/' . (int)$f[4], '6']; $n++;
		}
	}
	echo "$rir: $n Netze\n";
}
ksort($netze);
$gesamt = array_sum(array_map('count', $netze));
printf("Laender: %d, Netze: %d\n", count($netze), $gesamt);
if($fehler) { echo "Abbruch: nicht alle Registrierungsstellen erreichbar (" . implode(', ', $fehler) . "), Daten bleiben unveraendert\n"; exit(1); }
if($gesamt < 100000) { echo "Abbruch: zu wenige Netze, Daten bleiben unveraendert\n"; exit(1); }
if($dry) {
	foreach(['DE', 'US', 'CN', 'BR', 'AU'] as $cc) { printf("  %s: %d\n", $cc, count($netze[$cc] ?? [])); }
	exit(0);
}

// Namen der Laender aus der bisherigen Tabelle uebernehmen; neue Laender mit ihrem Code anlegen
$namen = [];
foreach($pdo->query("SELECT country, country_name FROM blocklisten_countries")->fetchAll(PDO::FETCH_ASSOC) as $r) { $namen[strtoupper($r['country'])] = $r['country_name']; }

$pdo->beginTransaction();
try {
	$pdo->exec("DELETE FROM bl_countries_ips");
	foreach($netze as $cc => $liste) {
		$name = $namen[$cc] ?? $cc;
		foreach(array_chunk($liste, 1000) as $teil) {
			$sql = "INSERT INTO bl_countries_ips (country, country_name, ip, typ) VALUES " . implode(',', array_fill(0, count($teil), '(?,?,?,?)'));
			$args = [];
			foreach($teil as [$ip, $typ]) { array_push($args, $cc, $name, $ip, $typ); }
			$pdo->prepare($sql)->execute($args);
		}
		if(!isset($namen[$cc])) {
			$pdo->prepare("INSERT INTO blocklisten_countries (country, country_name, file_name) VALUES (?, ?, ?)")->execute([$cc, $cc, $cc]);
		}
	}
	$pdo->commit();
} catch(Throwable $e) {
	$pdo->rollBack();
	echo "Fehler, nichts geaendert: " . $e->getMessage() . "\n";
	exit(1);
}
echo "bl_countries_ips ersetzt\n";
?>
