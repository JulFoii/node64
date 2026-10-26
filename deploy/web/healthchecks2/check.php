<?php
/** Healthchecks 2.0 – Detailseite eines Checks. */
ob_start(); // header.php gibt HTML aus; hc2_redirect()/hc2_json() verwerfen es
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
			case 'delete': $fw = hc2_failover_warning(hc2_failover_uses($uid, array($T))); hc2_delete_check($uid, $T); hc2_flash($fw !== '' ? 'warning' : 'success', 'Check gelöscht.' . ($fw !== '' ? ' ' . $fw : '')); hc2_redirect(HC2_BASE . '/');
			case 'run':
				if ($c['execution'] !== 'online' && hc2_check_nodes($c)) { foreach (hc2_check_nodes($c) as $rn) { hc2_command($rn, 'run_check', array('token' => $T)); } hc2_flash('info', count(hc2_check_nodes($c)) > 1 ? 'Sofortige Prüfung an ' . count(hc2_check_nodes($c)) . ' Nodes gegeben.' : 'Sofortige Prüfung an die Node gegeben.'); }
				else { hc2_flash('info', 'Online-Checks werden im Intervall geprüft; die nächste Messung folgt in Kürze.'); }
				break;
		}
	} catch (Throwable $e) { error_log('hc2 check: ' . $e->getMessage()); hc2_flash('danger', 'Aktion fehlgeschlagen.'); }
	hc2_redirect(HC2_BASE . '/check.php?token=' . $T);
}
$pdo = hc2_pdo();
$state = hc2_check_state($c);
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
		<?php if (in_array($c['type'], array('http', 'keyword', 'json'), true)) { echo hc2_cert_badge(hc2_cert_until(array_merge(array($c['last_message']), array_column($sources, 'last_message')))); } ?>
		<?php if ((int)$c['critical']) { echo '<span class="badge badge-danger">kritisch</span>'; } foreach (explode(',', $c['tags']) as $t) { if ($t !== '') { echo '<span class="badge badge-pill badge-secondary">' . hc2_h($t) . '</span>'; } } ?>
		<form method="post" class="ml-auto d-inline"><?php echo hc2_csrf_field(); ?>
			<a class="btn btn-sm btn-outline-secondary" href="<?php echo HC2_BASE; ?>/edit.php?token=<?php echo hc2_h($T); ?>"><i class="fa-solid fa-pen"></i> Bearbeiten</a>
			<a class="btn btn-sm btn-outline-secondary" href="<?php echo HC2_BASE; ?>/edit.php?clone=<?php echo hc2_h($T); ?>" title="Als Vorlage für einen neuen Check"><i class="fa-solid fa-copy"></i></a>
			<a class="btn btn-sm btn-outline-secondary" href="<?php echo HC2_BASE; ?>/move.php?tokens=<?php echo hc2_h($T); ?>" title="Ausführungsort ändern"><i class="fa-solid fa-right-left"></i> Umhängen</a>
			<?php if ((int)$c['paused']) { ?><button class="btn btn-sm btn-outline-success" name="action" value="resume"><i class="fa-solid fa-play"></i> Fortsetzen</button><?php } else { ?><button class="btn btn-sm btn-outline-secondary" name="action" value="pause"><i class="fa-solid fa-pause"></i> Pausieren</button><?php } ?>
			<?php if ($c['type'] !== 'push') { ?><button class="btn btn-sm btn-outline-secondary" name="action" value="run" title="Jetzt prüfen"><i class="fa-solid fa-rotate"></i></button><?php } ?>
			<?php $foUses = hc2_failover_uses($uid, array($T))[$T] ?? array(); ?>
			<button class="btn btn-sm btn-outline-danger" name="action" value="delete" onclick="return confirm(<?php echo hc2_h(json_encode('Check „' . $c['name'] . '“ mit allen Messdaten löschen?' . ($foUses ? "\n\nEr ist Monitor in DNS Failover: " . implode(', ', $foUses) . '. Die Policy zählt ihn danach nicht mehr.' : ''), JSON_UNESCAPED_UNICODE)); ?>);"><i class="fa-solid fa-trash"></i></button>
		</form>
	</div>
	<div class="text-muted small mb-3"><?php if ($c['target'] !== '') { echo '<code>' . hc2_h($c['target']) . '</code> · '; } ?>alle <?php echo (int)$c['interval_sec']; ?> s<?php if ($c['description'] !== '' && $c['description'] !== null) { echo ' · ' . nl2br(hc2_h($c['description'])); } if ($parent) { echo ' · abhängig von <a href="' . HC2_BASE . '/check.php?token=' . hc2_h($parent['token']) . '">' . hc2_h($parent['name']) . '</a>'; } ?></div>
	<?php if ($foUses) { echo '<div class="alert alert-info small"><i class="fa-solid fa-arrows-split-up-and-left"></i> Monitor in DNS Failover: <a href="/dns_failover">' . hc2_h(implode(', ', $foUses)) . '</a>. Pausieren oder Löschen wirkt sich dort aus – die Policy zählt den Check dann weder als online noch als gestört.</div>'; } ?>
	<?php if ($diag !== '') { echo '<div class="alert alert-info"><i class="fa-solid fa-stethoscope"></i> ' . hc2_h($diag) . '</div>'; } ?>
	<?php if ($state === 'quota') { echo '<div class="alert alert-secondary"><i class="fa-solid fa-hourglass-half"></i> <strong>Tageskontingent aufgebraucht.</strong> ipv64 misst diesen Check bis Mitternacht nicht mehr, danach wieder automatisch. Letzte Messung ' . hc2_ago($c['last_check_at'] ?? $c['state_since']) . '. <a href="/account?account_class">Mehr Messungen pro Tag</a></div>'; }
	elseif ($state === 'unchecked') { echo '<div class="alert alert-warning"><i class="fa-solid fa-hourglass-half"></i> <strong>Wird nicht überwacht.</strong> ' . hc2_h((string)$c['last_message']) . ' – ob der Dienst gerade erreichbar ist, ist unbekannt.</div>'; } ?>
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
					<?php $httpCol = in_array($c['type'], array('http', 'keyword', 'json'), true); ?>
					<thead><tr><th>Zeit</th><th>Messstelle</th><th>Ereignis</th><th>Grund</th><?php echo $httpCol ? '<th>HTTP</th>' : ''; ?><th>Details</th><th>Dauer</th></tr></thead><tbody>
					<?php if (!$events) { echo '<tr><td colspan="' . ($httpCol ? 7 : 6) . '" class="text-muted">Noch keine Ereignisse.</td></tr>'; } ?>
					<?php foreach ($events as $e) { $kinds = array('down' => array('Gestört', 'danger'), 'up' => array('Wieder OK', 'success'), 'degraded' => array('Teilweise gestört', 'warning'), 'degraded_end' => array('Wieder vollständig OK', 'success'), 'flapping_start' => array('Instabil', 'warning'), 'flapping_end' => array('Stabil', 'success'), 'reminder' => array('Erinnerung', 'secondary'), 'unchecked' => array('Nicht überwacht', 'warning'), 'rechecked' => array('Wird wieder geprüft', 'success'), 'state' => array('Zustand', 'secondary')); $k = $kinds[$e['kind']] ?? array($e['kind'], 'secondary'); ?>
					<tr><td class="text-nowrap small"><?php echo hc2_dt($e['time']); ?></td><td class="small"><?php echo hc2_h(hc2_source_label($e['source'], $nodes)); ?></td><td><span class="badge badge-<?php echo $k[1]; ?>"><?php echo hc2_h($k[0]); ?></span><?php echo ((int)$e['flags'] & 2) ? ' <small class="text-muted">(ohne Alarm)</small>' : ''; ?></td><td><?php echo hc2_reason_badge($e['reason']); ?></td><?php if ($httpCol) { echo '<td class="text-nowrap">' . hc2_http_badges((string)$e['message']) . '</td>'; } ?><td class="small text-break"><?php echo hc2_h((string)$e['message']); ?></td><td class="small text-nowrap"><?php echo (int)$e['duration_sec'] > 0 ? hc2_dur((int)$e['duration_sec']) : ''; ?></td></tr>
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
					<?php if ($c['execution'] !== 'online' && $c['node_id']) { ?>
					<div class="mb-1"><i class="fa-solid fa-house text-success"></i> <strong>Lokal</strong> an jeder Node des Accounts (Adresse der Node einsetzen, z. B. <?php echo hc2_h(hc2_nodes_label($nodes, hc2_check_nodes($c))); ?>):</div><code class="d-block mb-1 text-break">http://&lt;adresse-der-node&gt;:&lt;port&gt;/api/push/<?php echo hc2_h($T); ?></code>
					<div class="text-muted mb-2">Funktioniert im eigenen Netz auch ohne Internet. Die genaue Adresse steht in der Node auf der Detailseite des Checks.</div>
					<div class="mb-1"><i class="fa-solid fa-cloud text-primary"></i> <strong>Online</strong> über ipv64 (wird an alle messenden Nodes weitergereicht, solange sie verbunden sind):</div><code class="d-block mb-2 text-break">https://ipv64.net/health.php?token=<?php echo hc2_h($T); ?></code>
					<?php } else { ?>
					<div class="mb-1"><i class="fa-solid fa-cloud text-primary"></i> <strong>Online</strong>:</div><code class="d-block mb-2 text-break">https://ipv64.net/health.php?token=<?php echo hc2_h($T); ?></code>
					<?php } ?>
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
	// Legende filtert nach Messstelle: Klick = nur diese (nochmal = alle), Strg/Cmd/Umschalt-Klick = mehrere; bleibt beim Zeitraumwechsel
	var only = null;
	function applyOnly(ch){
		var names = ch.data.datasets.map(function(d){ return d.label; });
		if (only && !names.some(function(n){ return only.indexOf(n) >= 0; })) { only = null; }
		ch.data.datasets.forEach(function(d, i){ ch.setDatasetVisibility(i, !only || only.indexOf(d.label) >= 0); });
		ch.update();
	}
	function legendClick(e, item, legend){
		var ch = legend.chart, label = ch.data.datasets[item.datasetIndex].label, ev = e.native || {}, n = ch.data.datasets.length;
		if (ev.ctrlKey || ev.metaKey || ev.shiftKey) {
			var sel = (only || []).slice(), at = sel.indexOf(label);
			if (at >= 0) { sel.splice(at, 1); } else { sel.push(label); }
			only = sel.length && sel.length < n ? sel : null;
		} else {
			only = only && only.length === 1 && only[0] === label ? null : [label];
		}
		applyOnly(ch);
	}
	// Echte Zeitachse wie im Container: jede Messstelle hat eigene Zeitpunkte; Luecken nur bei Fehlern und Messpausen
	var spans = {'6h': 6 * 36e5, '24h': 24 * 36e5, '7d': 7 * 864e5, '30d': 30 * 864e5, '1y': 365 * 864e5};
	var steps = {'6h': 36e5, '24h': 3 * 36e5, '7d': 864e5, '30d': 5 * 864e5, '1y': 30 * 864e5};
	function pad(n){ return (n < 10 ? '0' : '') + n; }
	function fmt(ms, range, long){
		var t = new Date(ms), d = pad(t.getDate()) + '.' + pad(t.getMonth() + 1) + '.', hm = pad(t.getHours()) + ':' + pad(t.getMinutes());
		if (long) { return d + t.getFullYear() + (range === '1y' ? '' : ' ' + hm); }
		if (range === '6h' || range === '24h') { return hm; }
		if (range === '1y') { return pad(t.getMonth() + 1) + '/' + String(t.getFullYear()).substr(2); }
		return d;
	}
	function ticks(min, max, range){
		var out = [], d = new Date(min), step = steps[range];
		if (range === '1y') { d = new Date(d.getFullYear(), d.getMonth() + 1, 1); while (d.getTime() <= max) { out.push({value: d.getTime()}); d = new Date(d.getFullYear(), d.getMonth() + 1, 1); } return out; }
		if (step >= 864e5) { d.setHours(24, 0, 0, 0); } else { var mins = step / 6e4, cur = d.getHours() * 60 + d.getMinutes(); d.setSeconds(0, 0); d.setMinutes(Math.ceil(cur / mins) * mins - d.getHours() * 60); }
		for (var t = d.getTime(); t <= max; t += step) { out.push({value: t}); }
		return out;
	}
	function withGaps(pts){
		if (pts.length < 3) { return pts; }
		var diffs = []; for (var i = 1; i < pts.length; i++) { diffs.push(pts[i].x - pts[i - 1].x); }
		diffs.sort(function(a, b){ return a - b; });
		var limit = Math.max(3 * diffs[Math.floor(diffs.length / 2)], 120000), out = [pts[0]];
		for (var j = 1; j < pts.length; j++) { if (pts[j].x - pts[j - 1].x > limit) { out.push({x: pts[j - 1].x + 1, y: null}); } out.push(pts[j]); }
		return out;
	}
	function load(range){
		$.getJSON('<?php echo HC2_BASE; ?>/data.php', {token: '<?php echo hc2_h($T); ?>', range: range}, function(d){
			var raw = range === '6h' || range === '24h', now = Date.now(), xmin = now - spans[range];
			var ds = d.series.map(function(s, i){
				var pts = s.points.map(function(p){ return {x: Date.parse(p.t), y: p.ms}; }).sort(function(a, b){ return a.x - b.x; });
				return {label: s.label, data: withGaps(pts), borderColor: colors[i % colors.length], backgroundColor: colors[i % colors.length], borderWidth: 1.5, pointRadius: raw ? 1.5 : 0, pointHoverRadius: 4, spanGaps: false, tension: 0.2};
			});
			var cfg = {type: 'line', data: {datasets: ds}, options: {animation: false, interaction: {mode: 'nearest', axis: 'x', intersect: false},
				scales: {x: {type: 'linear', min: xmin, max: now, afterBuildTicks: function(axis){ axis.ticks = ticks(xmin, now, range); }, ticks: {autoSkip: false, callback: function(v){ return fmt(v, range, false); }}},
					y: {beginAtZero: true, title: {display: true, text: 'ms'}}},
				plugins: {legend: {display: ds.length > 1, onClick: legendClick}, tooltip: {callbacks: {
					title: function(items){ return items.length ? fmt(items[0].parsed.x, range, true) : ''; },
					label: function(it){ return it.dataset.label + ': ' + (it.parsed.y === null ? '–' : it.parsed.y + ' ms'); }}}}}};
			if (chart) { chart.destroy(); }
			chart = new Chart(document.getElementById('chart').getContext('2d'), cfg);
			if (only) { applyOnly(chart); }
			$('#chartnote').text((ds.length ? (raw ? 'Einzelmessungen je Messstelle; Lücken = gestört oder keine Messung' : 'Mittelwerte je ' + (range === '1y' ? 'Tag' : 'Stunde') + ' und Messstelle') : 'Noch keine Daten für diesen Zeitraum.')
				+ (ds.length > 1 ? '. Klick auf eine Messstelle in der Legende zeigt nur diese (nochmal: alle), mit Strg-Klick mehrere.' : ''));
		});
	}
	$('#ranges button').on('click', function(){ $('#ranges button').removeClass('active'); $(this).addClass('active'); load($(this).data('range')); });
	load('24h');
})();
</script>
