<?php
/**
 * Honeypot64 – deine Sensoren (Phase H2): eigene Sensoren und eigener Beitrag, bewusst schlank (Details in Node64).
 * Liest die Tabellen hp_* direkt (nur Zeilen des angemeldeten Accounts, ohne IPs). Ohne Menuelink; nur per URL.
 * Planung: docs/PLAN-NODE64-HONEYPOT64.md (Abschnitt 10) im Node64-Repo, Doku: https://node64.de/docs/honeypot/
 */
include("../header.php");

function hpw_h($s): string { return htmlspecialchars((string)$s, ENT_QUOTES, 'UTF-8'); }
/** UTC aus der DB -> Ortszeit der Seite */
function hpw_time($utc): string { return ($utc === null OR $utc === '') ? '–' : date('d.m.Y H:i', strtotime($utc . ' UTC')); }
function hpw_num($n): string { return number_format((int)$n, 0, ',', '.'); }
function hpw_rows(string $sql, array $p): array { global $pdo; $st = $pdo->prepare($sql); $st->execute($p); return $st->fetchAll(PDO::FETCH_ASSOC); }
?>
<p></p>
<div class="container">
<?php
if($userid == "") {
	echo '<div class="alert alert-info" role="alert">Bitte zuerst anmelden.</div></div>';
	include("../footer.php");
	exit;
}
$u = (int)$userid; $now = time();
$d1 = gmdate('Y-m-d H:i:s', $now - 86400); $d7 = gmdate('Y-m-d H:i:s', $now - 7 * 86400); $from = gmdate('Y-m-d', $now - 6 * 86400);
try {
	$sensors = hpw_rows("SELECT sensor_id, version, profile, mode, last_seen, reports, disabled FROM hp_sensors WHERE userid = :u AND last_seen IS NOT NULL ORDER BY last_seen DESC", array('u' => $u));
	$agg = array();
	foreach(hpw_rows("SELECT sensor_id, COUNT(DISTINCT CASE WHEN last_seen >= :d1 THEN ip_bin END) s24, COUNT(DISTINCT ip_bin) s7 FROM hp_report_sources
		WHERE userid = :u AND last_seen >= :d7 GROUP BY sensor_id", array('u' => $u, 'd1' => $d1, 'd7' => $d7)) as $x) { $agg[$x['sensor_id']] = $x; }
	$tot = hpw_rows("SELECT COUNT(DISTINCT CASE WHEN last_seen >= :d1 THEN ip_bin END) s24, COUNT(DISTINCT ip_bin) s7,
		COALESCE(SUM(CASE WHEN last_seen >= :d2 THEN `count` ELSE 0 END), 0) e24, COALESCE(SUM(`count`), 0) e7
		FROM hp_report_sources WHERE userid = :u AND last_seen >= :d7", array('u' => $u, 'd1' => $d1, 'd2' => $d1, 'd7' => $d7))[0];
	$kinds = hpw_rows("SELECT kind, SUM(events) e FROM hp_daily WHERE userid = :u AND day >= :d GROUP BY kind ORDER BY e DESC LIMIT 10", array('u' => $u, 'd' => $from));
	$ports = hpw_rows("SELECT service, port, SUM(events) e FROM hp_daily WHERE userid = :u AND day >= :d GROUP BY service, port ORDER BY e DESC LIMIT 10", array('u' => $u, 'd' => $from));
	$days = array();
	for($i = 6; $i >= 0; $i--) { $days[gmdate('Y-m-d', $now - $i * 86400)] = 0; }
	foreach(hpw_rows("SELECT day, SUM(events) e FROM hp_daily WHERE userid = :u AND day >= :d GROUP BY day", array('u' => $u, 'd' => $from)) as $x) { if(isset($days[$x['day']])) { $days[$x['day']] = (int)$x['e']; } }
} catch(Throwable $e) {
	error_log('honeypot/index.php: ' . $e->getMessage());
	echo '<div class="alert alert-danger" role="alert">Die Statistik ist gerade nicht verfügbar.</div></div>';
	include("../footer.php");
	exit;
}
$online = 0;
foreach($sensors as $s) { if(strtotime($s['last_seen'] . ' UTC') >= $now - 1800) { $online++; } }
$maxDay = max(1, max($days));
?>
	<div class="card mb-3"><div class="card-body">
		<h4 class="mb-2"><i class="fa-solid fa-bug text-primary"></i> Honeypot64 – deine Sensoren</h4>
		<p class="mb-1">Deine Node64-Sensoren melden alle 10 Minuten, welche IPs sie angegriffen haben. Aus den Meldungen mehrerer
		unabhängiger Beitragender entsteht die <b>v64 Blocklist</b> (folgt mit der Bewertung, Phase H3); als Beitragende/r bekommst du dann den Live-Stand.</p>
		<p class="mb-0 small text-muted">Einrichtung, Profile und Datenschutz: <a href="https://node64.de/docs/honeypot/" target="_blank" rel="noopener">node64.de/docs/honeypot/</a>.
		Details (Zugangsdaten, Pfade, Top-Angreifer) zeigt die Oberfläche bzw. Info-Seite deiner Node.</p>
	</div></div>

	<div class="row">
		<?php foreach(array(array('Sensoren online', $online . ' / ' . count($sensors)), array('Ereignisse 24 h', hpw_num($tot['e24'])), array('Ereignisse 7 Tage', hpw_num($tot['e7'])),
			array('Quell-IPs 24 h', hpw_num($tot['s24'])), array('Quell-IPs 7 Tage', hpw_num($tot['s7']))) as [$label, $val]) { ?>
		<div class="col-6 col-md pb-3"><div class="card h-100"><div class="card-body p-2 text-center">
			<div class="small text-muted"><?php echo hpw_h($label); ?></div><div class="h5 mb-0"><?php echo hpw_h($val); ?></div>
		</div></div></div>
		<?php } ?>
	</div>

	<div class="card mb-3"><div class="card-header p-2"><i class="fa-solid fa-satellite-dish text-primary"></i> Sensoren</div>
	<div class="card-body p-0"><div class="table-responsive">
		<table class="table table-sm mb-0 small"><thead><tr><th>Sensor</th><th>Status</th><th>Version</th><th>Profil</th><th>Letzte Meldung</th><th class="text-right">Meldungen</th><th class="text-right">Quell-IPs 24 h</th><th class="text-right">7 Tage</th></tr></thead><tbody>
		<?php if(empty($sensors)) { echo '<tr><td colspan="8" class="text-muted p-3">Noch kein Sensor hat gemeldet. Honeypot64 in Node64 einschalten und das Melden an ipv64 erlauben (Anleitung unter node64.de/docs/honeypot/).</td></tr>'; }
		foreach($sensors as $s) {
			$on = strtotime($s['last_seen'] . ' UTC') >= $now - 1800;
			$st = (int)$s['disabled'] === 1 ? '<span class="badge badge-danger">gesperrt</span>' : ($on ? '<span class="badge badge-success">online</span>' : '<span class="badge badge-secondary">offline</span>');
			$a = $agg[$s['sensor_id']] ?? array();
			echo '<tr><td><code title="' . hpw_h($s['sensor_id']) . '">' . hpw_h(substr($s['sensor_id'], 0, 8)) . '</code></td><td>' . $st . '</td><td>' . hpw_h($s['version']) . '</td><td>' . hpw_h($s['profile'])
				. ($s['mode'] === 'headless' ? ' <small class="text-muted">ohne Oberfläche</small>' : '') . '</td><td>' . hpw_h(hpw_time($s['last_seen'])) . '</td><td class="text-right">' . hpw_num($s['reports'])
				. '</td><td class="text-right">' . hpw_num($a['s24'] ?? 0) . '</td><td class="text-right">' . hpw_num($a['s7'] ?? 0) . '</td></tr>';
		} ?>
		</tbody></table>
	</div></div></div>

	<div class="row">
		<div class="col-12 col-lg-4 pb-3"><div class="card h-100"><div class="card-header p-2">Top-Arten (7 Tage)</div><div class="card-body p-0">
			<table class="table table-sm mb-0 small"><tbody>
			<?php if(empty($kinds)) { echo '<tr><td class="text-muted p-3">Noch keine Daten.</td></tr>'; }
			foreach($kinds as $k) { echo '<tr><td><code>' . hpw_h($k['kind']) . '</code></td><td class="text-right">' . hpw_num($k['e']) . '</td></tr>'; } ?>
			</tbody></table>
		</div></div></div>
		<div class="col-12 col-lg-4 pb-3"><div class="card h-100"><div class="card-header p-2">Top-Ports (7 Tage)</div><div class="card-body p-0">
			<table class="table table-sm mb-0 small"><tbody>
			<?php if(empty($ports)) { echo '<tr><td class="text-muted p-3">Noch keine Daten.</td></tr>'; }
			foreach($ports as $p) { echo '<tr><td>' . hpw_h($p['port']) . ' <small class="text-muted">' . hpw_h($p['service']) . '</small></td><td class="text-right">' . hpw_num($p['e']) . '</td></tr>'; } ?>
			</tbody></table>
		</div></div></div>
		<div class="col-12 col-lg-4 pb-3"><div class="card h-100"><div class="card-header p-2">Ereignisse je Tag (UTC)</div><div class="card-body p-2">
			<?php foreach($days as $day => $e) { ?>
			<div class="d-flex align-items-center small mb-1">
				<span style="width:4.5em"><?php echo hpw_h(date('d.m.', strtotime($day))); ?></span>
				<div class="progress flex-grow-1 mx-2" style="height:.6rem"><div class="progress-bar" style="width:<?php echo round($e / $maxDay * 100); ?>%"></div></div>
				<span class="text-right" style="width:5em"><?php echo hpw_num($e); ?></span>
			</div>
			<?php } ?>
		</div></div></div>
	</div>
	<p class="small text-muted">Online = Meldung in den letzten 30 Minuten. Gezählt werden nur öffentliche Quell-IPs; die IPs deiner eigenen Sensoren werden verworfen und nirgends angezeigt.</p>
</div>
<?php include("../footer.php"); ?>
