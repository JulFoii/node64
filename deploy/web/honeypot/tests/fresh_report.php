<?php
/**
 * Beispiel-Meldung (sample_report.json) auf die aktuelle Zeit schieben: Zeitraum = die letzten 10 Minuten, alle
 * Zeiten der Quellen gleich verschoben, report_id neu. Nur auf der Kommandozeile (nicht in den Webroot laden).
 *
 *   php fresh_report.php                 > /tmp/report.json   (Sensor-ID aus der Datei)
 *   php fresh_report.php --new-sensor    > /tmp/report.json   (neue zufaellige Sensor-ID)
 */
if(php_sapi_name() !== 'cli') { exit; }

function hp_uuid(): string {
	$b = random_bytes(16);
	$b[6] = chr((ord($b[6]) & 0x0f) | 0x40); $b[8] = chr((ord($b[8]) & 0x3f) | 0x80);
	return vsprintf('%s%s-%s-%s-%s-%s%s%s', str_split(bin2hex($b), 4));
}

/** Zeiten einer Meldung so verschieben, dass period.end = $end (Unix) ist; report_id neu. */
function hp_fresh(array $r, int $end, ?string $sensor = null): array {
	if($sensor !== null) { $r['sensor']['id'] = $sensor; }
	$ts = fn(string $t): int => (int)strtotime((string)preg_replace('/\.\d+/', '', $t)); // Bruchteile weglassen
	$shift = $end - $ts($r['period']['end']);
	$mv = fn(string $t): string => gmdate('Y-m-d\TH:i:s\Z', $ts($t) + $shift);
	$r['period']['start'] = $mv($r['period']['start']);
	$r['period']['end'] = $mv($r['period']['end']);
	foreach($r['sources'] as &$s) { $s['first'] = $mv($s['first']); $s['last'] = $mv($s['last']); }
	unset($s);
	$r['report_id'] = $r['sensor']['id'] . '-' . strtotime($r['period']['start']);
	return $r;
}

if(realpath($argv[0]) === __FILE__) {
	$r = json_decode(file_get_contents(__DIR__ . '/sample_report.json'), true);
	$r = hp_fresh($r, time() - 5, in_array('--new-sensor', $argv, true) ? hp_uuid() : null);
	echo json_encode($r, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE), "\n";
}
