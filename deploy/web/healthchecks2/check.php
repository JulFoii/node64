<?php
/** Healthchecks 2.0 – Detailseite eines Checks. */
include("../header.php");
require_once(__DIR__ . '/hc2_lib.php');
hc2_require_login();
$uid = (int)$userid;
$nodes = hc2_nodes($uid);
$c = hc2_check($uid, (string)($_GET['token'] ?? ''));
if (!$c) { echo '<div class="container"><div class="alert alert-danger mt-3">Check nicht gefunden.</div></div>'; include("../footer.php"); exit; }
$T = $c['token'];
if (hc2_is_post() && hc2_csrf_ok()) {
	$a = (string)($_POST['action'] ?? '');
	try {
		switch ($a) {
			case 'pause': hc2_set_check($uid, $T, array('paused' => 1)); hc2_flash('warning', 'Check pausiert.'); break;
			case 'resume': hc2_set_check($uid, $T, array('paused' => 0)); hc2_flash('success', 'Check fortgesetzt.'); break;
			case 'delete': hc2_delete_check($uid, $T); hc2_flash('success', 'Check gelöscht.'); hc2_redirect(HC2_BASE . '/');
			case 'run':
				if ($c['execution'] !== 'online' && $c['node_id']) { hc2_command($c['node_id'], 'run_check', array('token' => $T)); hc2_flash('info', 'Sofortige Prüfung an die Node gegeben.'); }
				else { hc2_flash('info', 'Online-Checks werden im Intervall geprüft; die nächste Messung folgt in Kürze.'); }
				break;
		}
	} catch (Throwable $e) { error_log('hc2 check: ' . $e->getMessage()); hc2_flash('danger', 'Aktion fehlgeschlagen.'); }
	hc2_redirect(HC2_BASE . '/check.php?token=' . $T);
}
$pdo = hc2_pdo();
$state = (int)$c['paused'] ? 'paused' : ($c['state'] ?: 'pending');
$st = $pdo->prepare("SELECT * FROM hc2_check_states WHERE token = :t ORDER BY source"); $st->execute(array('t' => $T)); $sources = $st->fetchAll(PDO::FETCH_ASSOC);
$st = $pdo->prepare("SELECT * FROM hc2_events WHERE token = :t ORDER BY id DESC LIMIT 50"); $st->execute(array('t' => $T)); $events = $st->fetchAll(PDO::FETCH_ASSOC);
$st = $pdo->prepare("SELECT * FROM hc2_incidents WHERE token = :t ORDER BY id DESC LIMIT 20"); $st->execute(array('t' => $T)); $incidents = $st->fetchAll(PDO::FETCH_ASSOC);
$st = $pdo->prepare("SELECT * FROM hc2_measurements WHERE token = :t ORDER BY time DESC LIMIT 1"); $st->execute(array('t' => $T)); $lastM = $st->fetch(PDO::FETCH_ASSOC);
$avail = hc2_availability($T);
$chanNames = array(); foreach (hc2_channels($uid) as $ch) { $chanNames[(int)$ch['id']] = $ch['name']; }
$parent = $c['parent_token'] ? hc2_check($uid, $c['parent_token']) : null;
$p = hc2_check_params($c);
// Diagnose innen/aussen
$diag = '';
if ($c['execution'] === 'both') {
	$in = null; $out = array();
	foreach ($sources as $s) { if (strncmp($s['source'], 'node:', 5) === 0) { $in = $s['state']; } elseif (strncmp($s['source'], 'loc:', 4) === 0) { $out[] = $s['state']; } }
	$outDown = $out && !in_array('up', $out, true); $outUp = $out && in_array('up', $out, true);
	if ($in === 'down' && $outUp) { $diag = 'Innen gestört, außen OK: Problem im Heimnetz, auf der Node oder im internen Pfad.'; }
	elseif ($in === 'up' && $outDown) { $diag = 'Innen OK, außen gestört: Internetanbindung, Portweiterleitung, DNS oder Firewall.'; }
	elseif ($in === 'down' && $outDown) { $diag = 'Innen und außen gestört: der Dienst selbst ist betroffen.'; }
}
?>
<p></p>
<div class="container">
	<?php echo hc2_subnav('index'); echo hc2_flash_out(); ?>
	<div class="d-flex flex-wrap align-items-center mb-2" style="gap:.5rem">
		<h4 class="mb-0"><?php echo hc2_h($c['name']); ?></h4>
		<?php echo hc2_state_badge($state); echo hc2_exec_badge($c, $nodes); ?>
		<span class="badge badge-light"><?php echo hc2_h(hc2_types()[$c['type']] ?? $c['type']); ?></span>
		<?php if ((int)$c['critical']) { echo '<span class="badge badge-danger">kritisch</span>'; } foreach (explode(',', $c['tags']) as $t) { if ($t !== '') { echo '<span class="badge badge-pill badge-secondary">' . hc2_h($t) . '</span>'; } } ?>
		<form method="post" class="ml-auto d-inline"><?php echo hc2_csrf_field(); ?>
			<a class="btn btn-sm btn-outline-secondary" href="<?php echo HC2_BASE; ?>/edit.php?token=<?php echo hc2_h($T); ?>"><i class="fa-solid fa-pen"></i> Bearbeiten</a>
			<a class="btn btn-sm btn-outline-secondary" href="<?php echo HC2_BASE; ?>/edit.php?clone=<?php echo hc2_h($T); ?>" title="Als Vorlage für einen neuen Check"><i class="fa-solid fa-copy"></i></a>
			<a class="btn btn-sm btn-outline-secondary" href="<?php echo HC2_BASE; ?>/move.php?tokens=<?php echo hc2_h($T); ?>" title="Ausführungsort ändern"><i class="fa-solid fa-right-left"></i> Umhängen</a>
			<?php if ((int)$c['paused']) { ?><button class="btn btn-sm btn-outline-success" name="action" value="resume"><i class="fa-solid fa-play"></i> Fortsetzen</button><?php } else { ?><button class="btn btn-sm btn-outline-secondary" name="action" value="pause"><i class="fa-solid fa-pause"></i> Pausieren</button><?php } ?>
			<?php if ($c['type'] !== 'push') { ?><button class="btn btn-sm btn-outline-secondary" name="action" value="run" title="Jetzt prüfen"><i class="fa-solid fa-rotate"></i></button><?php } ?>
			<button class="btn btn-sm btn-outline-danger" name="action" value="delete" onclick="return confirm('Check „<?php echo hc2_h($c['name']); ?>“ mit allen Messdaten löschen?');"><i class="fa-solid fa-trash"></i></button>
		</form>
	</div>
	<div class="text-muted small mb-3"><?php if ($c['target'] !== '') { echo '<code>' . hc2_h($c['target']) . '</code> · '; } ?>alle <?php echo (int)$c['interval_sec']; ?> s<?php if ($c['description'] !== '' && $c['description'] !== null) { echo ' · ' . nl2br(hc2_h($c['description'])); } if ($parent) { echo ' · abhängig von <a href="' . HC2_BASE . '/check.php?token=' . hc2_h($parent['token']) . '">' . hc2_h($parent['name']) . '</a>'; } ?></div>
	<?php if ($diag !== '') { echo '<div class="alert alert-info"><i class="fa-solid fa-stethoscope"></i> ' . hc2_h($diag) . '</div>'; } ?>
	<?php if ($state === 'down' || $state === 'degraded') { echo '<div class="alert alert-' . ($state === 'down' ? 'danger' : 'warning') . '"><strong>' . hc2_h(hc2_reason_text($c['last_reason'])) . '</strong> ' . hc2_h((string)$c['last_message']) . ' <span class="text-muted">seit ' . hc2_dt($c['down_since'] ?: $c['state_since']) . ' (' . hc2_ago($c['down_since'] ?: $c['state_since']) . ')</span></div>'; } ?>
	<div class="row">
		<div class="col-lg-8">
			<div class="card shadow-sm mb-3"><div class="card-body barr2 p-2 text-center" style="overflow-x:auto;white-space:nowrap"><?php echo hc2_pills($T, 60, $nodes); ?></div></div>
			<div class="card shadow-sm mb-3">
				<div class="card-header p-2 d-flex align-items-center"><span><i class="fa-solid fa-chart-line"></i> Latenz</span>
					<div class="btn-group btn-group-sm ml-auto" id="ranges"><?php foreach (array('6h' => '6 h', '24h' => '24 h', '7d' => '7 d', '30d' => '30 d', '1y' => '1 J') as $k => $v) { echo '<button class="btn btn-outline-secondary' . ($k === '24h' ? ' active' : '') . '" data-range="' . $k . '" type="button">' . $v . '</button>'; } ?></div></div>
				<div class="card-body"><canvas id="chart" height="110"></canvas><div class="small text-muted mt-1" id="chartnote"></div></div>
			</div>
			<div class="card shadow-sm mb-3">
				<div class="card-header p-2"><i class="fa-solid fa-list"></i> Ereignisse</div>
				<div class="table-responsive"><table class="table table-sm mb-0">
					<thead><tr><th>Zeit</th><th>Messstelle</th><th>Ereignis</th><th>Grund</th><th>Dauer</th></tr></thead><tbody>
					<?php if (!$events) { echo '<tr><td colspan="5" class="text-muted">Noch keine Ereignisse.</td></tr>'; } ?>
					<?php foreach ($events as $e) { $kinds = array('down' => array('Gestört', 'danger'), 'up' => array('Wieder OK', 'success'), 'degraded' => array('Teilweise gestört', 'warning'), 'degraded_end' => array('Wieder vollständig OK', 'success'), 'flapping_start' => array('Instabil', 'warning'), 'flapping_end' => array('Stabil', 'success'), 'reminder' => array('Erinnerung', 'secondary')); $k = $kinds[$e['kind']] ?? array($e['kind'], 'secondary'); ?>
					<tr><td class="text-nowrap small"><?php echo hc2_dt($e['time']); ?></td><td class="small"><?php echo hc2_h(hc2_source_label($e['source'], $nodes)); ?></td><td><span class="badge badge-<?php echo $k[1]; ?>"><?php echo hc2_h($k[0]); ?></span><?php echo ((int)$e['flags'] & 2) ? ' <small class="text-muted">(ohne Alarm)</small>' : ''; ?></td><td class="small"><?php echo hc2_h(hc2_reason_text($e['reason'])); echo $e['message'] ? ' – ' . hc2_h($e['message']) : ''; ?></td><td class="small text-nowrap"><?php echo (int)$e['duration_sec'] > 0 ? hc2_dur((int)$e['duration_sec']) : ''; ?></td></tr>
					<?php } ?>
					</tbody></table></div>
			</div>
			<div class="card shadow-sm mb-3">
				<div class="card-header p-2"><i class="fa-solid fa-triangle-exclamation"></i> Störungen</div>
				<div class="table-responsive"><table class="table table-sm mb-0">
					<thead><tr><th>Beginn</th><th>Ende</th><th>Dauer</th><th>Grund</th><th>Messstellen</th></tr></thead><tbody>
					<?php if (!$incidents) { echo '<tr><td colspan="5" class="text-muted">Keine Störungen.</td></tr>'; } ?>
					<?php foreach ($incidents as $i) { $dur = (strtotime(($i['ended_at'] ?: gmdate('Y-m-d H:i:s')) . ' UTC') - strtotime($i['started_at'] . ' UTC')); ?>
					<tr><td class="small text-nowrap"><?php echo hc2_dt($i['started_at']); ?></td><td class="small text-nowrap"><?php echo $i['ended_at'] ? hc2_dt($i['ended_at']) : '<span class="badge badge-danger">offen</span>'; ?></td><td class="small"><?php echo hc2_dur(max(0, $dur)); ?></td><td class="small"><?php echo hc2_h(hc2_reason_text($i['reason'])); echo $i['message'] ? ' – ' . hc2_h($i['message']) : ''; ?></td><td class="small"><?php $sl = array(); foreach (explode(',', $i['sources']) as $s) { if ($s !== '') { $sl[] = hc2_source_label($s, $nodes); } } echo hc2_h(implode(', ', $sl)); ?></td></tr>
					<?php } ?>
					</tbody></table></div>
			</div>
		</div>
		<div class="col-lg-4">
			<div class="card shadow-sm mb-3">
				<div class="card-header p-2"><i class="fa-solid fa-percent"></i> Verfügbarkeit</div>
				<div class="card-body p-2"><div class="row text-center">
					<?php foreach (array('24h' => '24 Stunden', '30d' => '30 Tage', '1y' => '1 Jahr') as $k => $v) { echo '<div class="col-4"><div class="h5 mb-0">' . ($avail[$k] === null ? '–' : rtrim(rtrim(number_format($avail[$k], 3, ',', ''), '0'), ',') . ' %') . '</div><small class="text-muted">' . $v . '</small></div>'; } ?>
				</div><div class="small text-muted mt-1">über alle Messstellen</div></div>
			</div>
			<div class="card shadow-sm mb-3">
				<div class="card-header p-2"><i class="fa-solid fa-location-dot"></i> Messstellen</div>
				<ul class="list-group list-group-flush">
					<?php if (!$sources) { echo '<li class="list-group-item small text-muted">Noch keine Messung.</li>'; } ?>
					<?php foreach ($sources as $s) { $isNode = strncmp($s['source'], 'node:', 5) === 0; $stale = $isNode ? (isset($nodes[substr($s['source'], 5)]) && !(int)$nodes[substr($s['source'], 5)]['online']) : false; ?>
					<li class="list-group-item p-2"><div class="d-flex align-items-center"><span><i class="fa-solid <?php echo $isNode ? 'fa-house' : 'fa-cloud'; ?>"></i> <?php echo hc2_h(hc2_source_label($s['source'], $nodes)); ?></span><span class="ml-auto"><?php echo hc2_state_badge($s['state']); ?></span></div>
						<div class="small text-muted"><?php echo hc2_h(hc2_reason_text($s['last_reason'])); echo $s['last_message'] ? ' – ' . hc2_h(mb_substr($s['last_message'], 0, 120)) : ''; ?><br><?php echo $s['last_latency_ms'] !== null ? round((float)$s['last_latency_ms'], 1) . ' ms · ' : ''; ?>zuletzt <?php echo hc2_ago($s['last_check_at']); ?><?php echo $stale ? ' · <span class="text-warning">Node offline</span>' : ''; ?></div></li>
					<?php } ?>
				</ul>
				<?php if ($c['execution'] === 'both') { echo '<div class="card-footer p-2 small text-muted">Regel: ' . array('all' => 'gestört nur, wenn alle Messstellen gestört', 'any' => 'gestört, sobald eine Messstelle gestört', 'majority' => 'gestört bei Mehrheit')[$c['policy']] . '</div>'; } ?>
			</div>
			<?php if ($c['type'] === 'push') { ?>
			<div class="card shadow-sm mb-3">
				<div class="card-header p-2"><i class="fa-solid fa-satellite-dish"></i> Push-URLs</div>
				<div class="card-body p-2 small">
					<div class="mb-1">Online (immer):</div><code class="d-block mb-2 text-break">https://ipv64.net/health.php?token=<?php echo hc2_h($T); ?></code>
					<?php if ($c['execution'] !== 'online' && $c['node_id']) { ?><div class="mb-1">Lokal an der Node <?php echo hc2_h(hc2_node_label($nodes, $c['node_id'])); ?> (Adresse der Node, Pfad):</div><code class="d-block mb-2 text-break">http://&lt;node&gt;/api/push/<?php echo hc2_h($T); ?></code><?php } ?>
					<div class="text-muted">Optional <code>?status=down&amp;msg=…</code> für eine aktive Störungsmeldung. Erwarteter Abstand <?php echo (int)($p['period_seconds'] ?? 3600); ?> s, Kulanz <?php echo (int)($p['grace_seconds'] ?? 600); ?> s.</div>
				</div>
			</div>
			<?php } ?>
			<div class="card shadow-sm mb-3">
				<div class="card-header p-2"><i class="fa-solid fa-gear"></i> Einstellungen</div>
				<div class="card-body p-2 small">
					<div>Intervall <?php echo (int)$c['interval_sec']; ?> s, Wiederholung <?php echo (int)$c['retry_interval_sec']; ?> s × <?php echo (int)$c['retries']; ?>, Stabilisierung <?php echo (int)$c['stabilize']; ?></div>
					<div>Timeouts <?php echo $c['connect_timeout_ms'] / 1000; ?> s / <?php echo $c['total_timeout_ms'] / 1000; ?> s, IP: <?php echo hc2_h($c['ip_mode']); ?><?php echo (int)$c['invert'] ? ', invertiert' : ''; ?></div>
					<div>Alarm: <?php echo (int)$c['notify_down'] ? 'Störung' : ''; echo (int)$c['notify_up'] ? ', Entwarnung' : ''; echo (int)$c['notify_degraded'] ? ', teilweise' : ''; echo (int)$c['repeat_minutes'] ? ', Erinnerung alle ' . (int)$c['repeat_minutes'] . ' min' : ''; ?></div>
					<div>Kanäle: <?php $cn = array(); foreach (hc2_check_channels($c) as $id) { $cn[] = $chanNames[$id] ?? ('#' . $id); } echo $cn ? hc2_h(implode(', ', $cn)) : 'Standardkanäle'; ?></div>
					<?php if ($p) { echo '<div class="mt-1">Parameter: <code class="text-break">' . hc2_h(json_encode($p, JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE)) . '</code></div>'; } ?>
					<div class="text-muted mt-1">Token <code><?php echo hc2_h($T); ?></code> · Revision <?php echo (int)$c['revision']; ?> · angelegt <?php echo hc2_dt($c['created_at'], 'd.m.Y'); ?></div>
				</div>
			</div>
			<?php if ($lastM) { ?>
			<div class="card shadow-sm mb-3">
				<div class="card-header p-2"><i class="fa-solid fa-magnifying-glass"></i> Letzte Messung roh</div>
				<div class="card-body p-2 small"><div><?php echo hc2_dt($lastM['time']); ?> · <?php echo hc2_h(hc2_source_label($lastM['source'], $nodes)); ?> · <?php echo (int)$lastM['status'] === 1 ? 'OK' : 'Fehler'; ?> · <?php echo round((float)$lastM['latency_ms'], 2); ?> ms<?php echo $lastM['family'] ? ' · ' . $lastM['family'] : ''; ?></div>
					<?php if ($lastM['message']) { echo '<div>' . hc2_h($lastM['message']) . '</div>'; } if ($lastM['details']) { echo '<pre class="mb-0 mt-1" style="white-space:pre-wrap;max-height:200px;overflow:auto">' . hc2_h(json_encode(json_decode($lastM['details']), JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE)) . '</pre>'; } ?></div>
			</div>
			<?php } ?>
		</div>
	</div>
</div>
<?php include("../footer.php"); ?>
<script src="/js/chart.js"></script>
<script>
(function(){
	$('[data-toggle="tooltip"]').tooltip();
	var chart = null, colors = ['#007bff','#28a745','#fd7e14','#6f42c1','#20c997'];
	function load(range){
		$.getJSON('<?php echo HC2_BASE; ?>/data.php', {token: '<?php echo hc2_h($T); ?>', range: range}, function(d){
			var labels = []; d.series.forEach(function(s){ s.points.forEach(function(p){ if (labels.indexOf(p.t) < 0) { labels.push(p.t); } }); }); labels.sort();
			var ds = d.series.map(function(s, i){ var m = {}; s.points.forEach(function(p){ m[p.t] = p.ms; }); return {label: s.label, data: labels.map(function(t){ return m.hasOwnProperty(t) ? m[t] : null; }), borderColor: colors[i % colors.length], backgroundColor: colors[i % colors.length], borderWidth: 1.5, pointRadius: (range === '6h' || range === '24h') ? 1.5 : 0, spanGaps: false, tension: 0.2}; });
			var cfg = {type: 'line', data: {labels: labels, datasets: ds}, options: {animation: false, scales: {x: {ticks: {maxTicksLimit: 8, callback: function(v, i){ var t = labels[i] || ''; return t.substr(5, 11).replace('T', ' '); }}}, y: {beginAtZero: true, title: {display: true, text: 'ms'}}}, plugins: {legend: {display: ds.length > 1}, tooltip: {callbacks: {title: function(items){ return (labels[items[0].dataIndex] || '').substr(0, 19).replace('T', ' '); }}}}}};
			if (chart) { chart.destroy(); }
			chart = new Chart(document.getElementById('chart').getContext('2d'), cfg);
			$('#chartnote').text(ds.length ? (range === '6h' || range === '24h' ? 'Einzelmessungen; Lücken = Fehler' : 'Mittelwerte je ' + (range === '1y' ? 'Tag' : 'Stunde')) : 'Noch keine Daten für diesen Zeitraum.');
		});
	}
	$('#ranges button').on('click', function(){ $('#ranges button').removeClass('active'); $(this).addClass('active'); load($(this).data('range')); });
	load('24h');
})();
</script>
