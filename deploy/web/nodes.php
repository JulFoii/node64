<?php
/**
 * Healthchecks 2.0: Meine Nodes – Liste und Detail (Checks der Node, Konflikte, Umbenennen, Fernverwaltung,
 * Token widerrufen, entfernen). Bewusst ohne Menülink; nur per URL erreichbar.
 */
ob_start(); // header.php gibt HTML aus; hc2_redirect()/hc2_json() verwerfen es
include("header.php");
require_once(__DIR__ . '/healthchecks2/hc2_lib.php');
hc2_require_login();
$uid = (int)$userid; $pdo = hc2_pdo();
$msg = '';
$nid = preg_replace('/[^A-Za-z0-9_-]/', '', (string)($_GET['node'] ?? $_POST['node_id'] ?? ''));
$loadNode = function(string $id) use ($pdo, $uid) { if ($id === '') { return null; } $st = $pdo->prepare("SELECT * FROM hc2_nodes WHERE node_id = :n AND userid = :u"); $st->execute(array('n' => $id, 'u' => $uid)); return $st->fetch(PDO::FETCH_ASSOC) ?: null; };

if (hc2_is_post() && hc2_csrf_ok()) {
	$node = $loadNode($nid); $action = (string)($_POST['action'] ?? '');
	try {
		if ($node) {
			switch ($action) {
				case 'revoke':
					$pdo->prepare("UPDATE hc2_node_tokens SET revoked_at = UTC_TIMESTAMP(3) WHERE node_id = :n AND revoked_at IS NULL")->execute(array('n' => $nid));
					$pdo->prepare("UPDATE hc2_nodes SET revoked_at = UTC_TIMESTAMP(3), online = 0 WHERE node_id = :n")->execute(array('n' => $nid));
					hc2_log_change($uid, 'node', $nid, 'delete', 'portal');
					hc2_signal('hc2:node:' . $nid, 'revoke');
					$keep = !empty($_POST['keep_checks']);
					$st = $pdo->prepare("SELECT * FROM hc2_checks WHERE node_id = :n AND userid = :u AND deleted_at IS NULL AND execution IN ('local','both')"); $st->execute(array('n' => $nid, 'u' => $uid));
					$kept = 0; $dropped = 0;
					foreach ($st->fetchAll(PDO::FETCH_ASSOC) as $c) {
						$acc = hc2_account($uid); $locs = array_filter(explode(',', $c['locations'])) ?: array_keys(hc2_locations());
						$fits = $keep && !hc2_private_target($c['type'], $c['target']) && ($acc['healthcheck_limit'] <= 0 || hc2_online_used($uid, $c['token']) + count($locs) <= $acc['healthcheck_limit']);
						if ($fits) { hc2_set_check($uid, $c['token'], array('execution' => 'online', 'node_id' => null)); $kept++; } else { hc2_delete_check($uid, $c['token']); $dropped++; }
					}
					$msg = 'Node getrennt. ' . ($keep ? $kept . ' Check(s) laufen online weiter, ' . $dropped . ' gelöscht (privates Ziel oder Limit).' : $dropped . ' Check(s) der Node gelöscht.');
					$nid = '';
					break;
				case 'rename':
					$name = mb_substr(trim((string)($_POST['name'] ?? '')), 0, 100); $loc = mb_substr(trim((string)($_POST['location'] ?? '')), 0, 100);
					$rm = in_array($_POST['remote_mgmt'] ?? '', array('off','read','full'), true) ? $_POST['remote_mgmt'] : $node['remote_mgmt'];
					if ($name !== '') {
						$pdo->prepare("UPDATE hc2_nodes SET name = :na, location = :l, remote_mgmt = :r WHERE node_id = :n")->execute(array('na' => $name, 'l' => $loc, 'r' => $rm, 'n' => $nid));
						hc2_log_change($uid, 'node', $nid, 'upsert', 'portal'); $msg = 'Node gespeichert.';
					}
					break;
				case 'command':
					$name = in_array($_POST['cmd'] ?? '', array('run_check', 'repair'), true) ? $_POST['cmd'] : '';
					$token = preg_replace('/[^A-Za-z0-9]/', '', (string)($_POST['token'] ?? ''));
					if ($name !== '') { hc2_command($nid, $name, $token !== '' ? array('token' => $token) : array()); $msg = 'Befehl an die Node gegeben.'; }
					break;
				case 'resolve':
					$keep = ($_POST['keep'] ?? 'server') === 'local' ? 'local' : 'server';
					hc2_command($nid, 'resolve_conflict', array('id' => (int)($_POST['conflict_id'] ?? 0), 'keep' => $keep));
					$msg = 'Konfliktlösung an die Node gegeben (' . ($keep === 'server' ? 'Server-Version' : 'Node-Version') . ').';
					break;
			}
		}
	} catch (Throwable $e) { error_log('nodes.php: ' . $e->getMessage()); $msg = 'Aktion fehlgeschlagen.'; }
}
$st = $pdo->prepare("SELECT n.*, (SELECT COUNT(*) FROM hc2_checks c WHERE c.node_id = n.node_id AND c.deleted_at IS NULL AND c.execution IN ('local','both')) AS checks FROM hc2_nodes n WHERE userid = :u ORDER BY revoked_at IS NOT NULL, created_at DESC");
$st->execute(array('u' => $uid)); $nodes = $st->fetchAll(PDO::FETCH_ASSOC);
$detail = $loadNode($nid); $nodeMap = hc2_nodes($uid);
?>
<p></p>
<div class="container">
	<?php echo hc2_subnav('nodes'); if ($msg !== '') { echo '<div class="alert alert-info">' . hc2_h($msg) . '</div>'; } ?>
	<div class="card shadow-sm mb-3">
		<div class="card-header p-2 d-flex justify-content-between align-items-center"><span><i class="fa-solid fa-server"></i> Meine Nodes</span><a class="btn btn-sm btn-primary" href="link.php"><i class="fa-solid fa-link"></i> Node verknüpfen</a></div>
		<?php if (!$nodes) { ?><div class="card-body"><p class="text-muted mb-0">Noch keine Node verknüpft. Node64 installieren, dort unter <em>ipv64-Verknüpfung</em> einen Code anfordern und unter <a href="link.php">Node verknüpfen</a> eingeben.</p></div><?php } else { ?>
		<div class="table-responsive"><table class="table table-sm mb-0">
			<thead><tr><th>Name</th><th>Standort</th><th>Status</th><th>Version</th><th>Letzter Abgleich</th><th>Checks</th><th>Ausstehend</th><th>Fernverwaltung</th><th></th></tr></thead>
			<tbody>
			<?php foreach ($nodes as $n) { $revoked = !empty($n['revoked_at']); ?>
			<tr<?php echo $revoked ? ' class="text-muted"' : ''; ?>>
				<td><?php echo $revoked ? hc2_h($n['name']) : '<a href="nodes.php?node=' . hc2_h($n['node_id']) . '">' . hc2_h($n['name']) . '</a>'; ?><br><small class="text-muted"><?php echo hc2_h($n['node_id']); ?></small></td>
				<td><?php echo hc2_h($n['location']); ?></td>
				<td><?php if ($revoked) { echo '<span class="badge badge-secondary">getrennt</span>'; } elseif ((int)$n['online'] === 1) { echo '<span class="badge badge-success">online</span> <small class="text-muted">' . hc2_h($n['node']) . '</small>'; } else { echo '<span class="badge badge-warning">offline</span><br><small class="text-muted">seit ' . hc2_dt($n['last_seen']) . '</small>'; } ?></td>
				<td><?php echo hc2_h($n['version']); ?></td>
				<td class="small"><?php echo hc2_dt($n['last_sync']); ?></td>
				<td><?php echo (int)$n['checks']; ?></td>
				<td><?php echo (int)$n['outbox_size']; if ((int)$n['conflicts'] > 0) { echo ' <span class="badge badge-danger">' . (int)$n['conflicts'] . ' Konflikte</span>'; } ?></td>
				<td><?php echo array('off' => 'aus', 'read' => 'lesen + Tests', 'full' => 'vollständig')[$n['remote_mgmt']] ?? hc2_h($n['remote_mgmt']); ?></td>
				<td class="text-nowrap text-right"><?php if (!$revoked) { ?><a class="btn btn-sm btn-outline-secondary" href="nodes.php?node=<?php echo hc2_h($n['node_id']); ?>">Details</a><?php } ?></td>
			</tr>
			<?php } ?>
			</tbody>
		</table></div>
		<?php } ?>
	</div>
	<?php if ($detail && empty($detail['revoked_at'])) { $N = $detail['node_id'];
		$st = $pdo->prepare("SELECT * FROM hc2_checks WHERE node_id = :n AND userid = :u AND deleted_at IS NULL AND execution IN ('local','both') ORDER BY name"); $st->execute(array('n' => $N, 'u' => $uid)); $nchecks = $st->fetchAll(PDO::FETCH_ASSOC);
		$st = $pdo->prepare("SELECT * FROM hc2_commands WHERE node_id = :n ORDER BY id DESC LIMIT 10"); $st->execute(array('n' => $N)); $cmds = $st->fetchAll(PDO::FETCH_ASSOC);
		$pills = hc2_pills_many(array_column($nchecks, 'token'), 20, $nodeMap);
	?>
	<div class="row">
		<div class="col-lg-8">
			<div class="card shadow-sm mb-3">
				<div class="card-header p-2 d-flex align-items-center"><span><i class="fa-solid fa-heart-pulse"></i> Checks von <?php echo hc2_h($detail['name']); ?> <span class="badge badge-secondary"><?php echo count($nchecks); ?></span></span>
					<span class="ml-auto"><a class="btn btn-sm btn-primary" href="<?php echo HC2_BASE; ?>/edit.php?node=<?php echo hc2_h($N); ?>"><i class="fa-solid fa-plus"></i> Check auf dieser Node anlegen</a></span></div>
				<div class="table-responsive"><table class="table table-sm mb-0">
					<thead><tr><th>Zustand</th><th>Name</th><th>Typ</th><th>Messungen</th><th></th></tr></thead><tbody>
					<?php if (!$nchecks) { echo '<tr><td colspan="5" class="text-muted">Keine Checks auf dieser Node. Checks lassen sich in der Node anlegen oder hier (die Node übernimmt sie, solange die Fernverwaltung nicht „aus“ ist).</td></tr>'; } ?>
					<?php foreach ($nchecks as $c) { ?>
					<tr><td><?php echo hc2_state_badge((int)$c['paused'] ? 'paused' : ($c['state'] ?: 'pending')); ?></td>
						<td><a href="<?php echo HC2_BASE; ?>/check.php?token=<?php echo hc2_h($c['token']); ?>"><?php echo hc2_h($c['name']); ?></a> <?php echo $c['execution'] === 'both' ? '<span class="badge badge-light">hybrid</span>' : ''; ?><br><small class="text-muted"><?php echo hc2_h($c['target']); ?></small></td>
						<td><span class="badge badge-light"><?php echo hc2_h(hc2_types()[$c['type']] ?? $c['type']); ?></span></td>
						<td class="barr2 text-nowrap"><?php echo $pills[$c['token']] ?? ''; ?></td>
						<td class="text-right text-nowrap"><form method="post" class="d-inline"><?php echo hc2_csrf_field(); ?><input type="hidden" name="node_id" value="<?php echo hc2_h($N); ?>"><input type="hidden" name="action" value="command"><input type="hidden" name="cmd" value="run_check"><input type="hidden" name="token" value="<?php echo hc2_h($c['token']); ?>"><button class="btn btn-sm btn-outline-secondary" title="Jetzt prüfen"><i class="fa-solid fa-rotate"></i></button></form>
							<a class="btn btn-sm btn-outline-secondary" href="<?php echo HC2_BASE; ?>/move.php?tokens=<?php echo hc2_h($c['token']); ?>&to=online" title="Online umhängen"><i class="fa-solid fa-cloud-arrow-up"></i></a></td></tr>
					<?php } ?>
					</tbody></table></div>
			</div>
			<?php if ((int)$detail['conflicts'] > 0) { ?>
			<div class="card shadow-sm mb-3 border-danger">
				<div class="card-header p-2"><i class="fa-solid fa-code-merge"></i> Konflikte: <?php echo (int)$detail['conflicts']; ?></div>
				<div class="card-body small">
					<p>Die Node hat Änderungen, die sich mit Änderungen hier überschneiden (sie war zwischendurch offline). Die beiden Versionen zeigt die Node unter <em>ipv64-Verknüpfung</em>. Du kannst die Entscheidung auch von hier an die Node geben:</p>
					<form method="post" class="form-inline" style="gap:.4rem"><?php echo hc2_csrf_field(); ?><input type="hidden" name="node_id" value="<?php echo hc2_h($N); ?>"><input type="hidden" name="action" value="resolve">
						<input class="form-control form-control-sm" type="number" name="conflict_id" placeholder="Konflikt-Nr. (aus der Node)" min="1" required>
						<button class="btn btn-sm btn-outline-primary" name="keep" value="server">Server-Version behalten</button><button class="btn btn-sm btn-outline-secondary" name="keep" value="local">Node-Version übernehmen</button></form>
				</div>
			</div>
			<?php } ?>
			<div class="card shadow-sm mb-3">
				<div class="card-header p-2"><i class="fa-solid fa-terminal"></i> Letzte Befehle</div>
				<div class="table-responsive"><table class="table table-sm mb-0"><thead><tr><th>Zeit</th><th>Befehl</th><th>Ergebnis</th></tr></thead><tbody>
					<?php if (!$cmds) { echo '<tr><td colspan="3" class="text-muted">Keine Befehle.</td></tr>'; } foreach ($cmds as $cm) { ?><tr><td class="small text-nowrap"><?php echo hc2_dt($cm['created_at']); ?></td><td class="small"><?php echo hc2_h($cm['name']); ?></td><td class="small"><?php echo $cm['done_at'] ? ((int)$cm['ok'] ? '<span class="text-success">OK</span>' : '<span class="text-danger">Fehler</span>') . ' ' . hc2_h(mb_substr((string)$cm['output'], 0, 120)) : '<span class="text-muted">offen</span>'; ?></td></tr><?php } ?>
					</tbody></table></div>
			</div>
		</div>
		<div class="col-lg-4">
			<div class="card shadow-sm mb-3">
				<div class="card-header p-2"><i class="fa-solid fa-server"></i> Node</div>
				<div class="card-body">
					<form method="post"><?php echo hc2_csrf_field(); ?><input type="hidden" name="node_id" value="<?php echo hc2_h($N); ?>"><input type="hidden" name="action" value="rename">
						<div class="form-group"><label>Name</label><input class="form-control" name="name" value="<?php echo hc2_h($detail['name']); ?>" maxlength="100" required></div>
						<div class="form-group"><label>Standort</label><input class="form-control" name="location" value="<?php echo hc2_h($detail['location']); ?>" maxlength="100"></div>
						<div class="form-group"><label>Fernverwaltung</label><select class="custom-select" name="remote_mgmt"><option value="read"<?php echo $detail['remote_mgmt'] === 'read' ? ' selected' : ''; ?>>Nur lesen und Testläufe</option><option value="full"<?php echo $detail['remote_mgmt'] === 'full' ? ' selected' : ''; ?>>Vollständig</option><option value="off"<?php echo $detail['remote_mgmt'] === 'off' ? ' selected' : ''; ?>>Aus</option></select><small class="form-text text-muted">Die Node entscheidet selbst, was sie annimmt; die Einstellung wird mit dem nächsten Abgleich übertragen.</small></div>
						<button class="btn btn-primary btn-sm" type="submit">Speichern</button>
					</form>
					<hr>
					<dl class="row small mb-0">
						<dt class="col-5">Status</dt><dd class="col-7"><?php echo (int)$detail['online'] ? '<span class="badge badge-success">online</span> an ' . hc2_h($detail['node']) : '<span class="badge badge-warning">offline</span> seit ' . hc2_dt($detail['last_seen']); ?></dd>
						<dt class="col-5">Version</dt><dd class="col-7"><?php echo hc2_h($detail['version']); ?></dd>
						<dt class="col-5">Zeitzone</dt><dd class="col-7"><?php echo hc2_h($detail['timezone']); ?></dd>
						<dt class="col-5">Module</dt><dd class="col-7"><?php echo hc2_h($detail['modules'] ?: '–'); ?></dd>
						<dt class="col-5">Letzter Abgleich</dt><dd class="col-7"><?php echo hc2_dt($detail['last_sync']); ?></dd>
						<dt class="col-5">Postausgang</dt><dd class="col-7"><?php echo (int)$detail['outbox_size']; ?> offen</dd>
						<dt class="col-5">Verknüpft seit</dt><dd class="col-7"><?php echo hc2_dt($detail['created_at'], 'd.m.Y'); ?></dd>
						<dt class="col-5">ID</dt><dd class="col-7"><code><?php echo hc2_h($N); ?></code></dd>
					</dl>
				</div>
			</div>
			<div class="card shadow-sm mb-3">
				<div class="card-header p-2"><i class="fa-solid fa-screwdriver-wrench"></i> Aktionen</div>
				<div class="card-body">
					<form method="post" class="mb-2"><?php echo hc2_csrf_field(); ?><input type="hidden" name="node_id" value="<?php echo hc2_h($N); ?>"><input type="hidden" name="action" value="command"><input type="hidden" name="cmd" value="repair"><button class="btn btn-sm btn-outline-secondary" type="submit"><i class="fa-solid fa-arrows-rotate"></i> Vollabgleich anstoßen</button></form>
					<form method="post" onsubmit="return confirm('Node trennen? Sie läuft danach standalone weiter.');"><?php echo hc2_csrf_field(); ?><input type="hidden" name="node_id" value="<?php echo hc2_h($N); ?>"><input type="hidden" name="action" value="revoke">
						<div class="custom-control custom-checkbox mb-2"><input class="custom-control-input" type="checkbox" id="keep_checks" name="keep_checks" value="1" checked><label class="custom-control-label" for="keep_checks">Checks als Online-Checks weiterführen (öffentliche Ziele, soweit das Limit reicht)</label></div>
						<button class="btn btn-sm btn-outline-danger" type="submit"><i class="fa-solid fa-link-slash"></i> Node trennen (Token widerrufen)</button>
					</form>
				</div>
			</div>
		</div>
	</div>
	<?php } ?>
</div>
<?php include("footer.php"); ?>
<script>$(function(){ $('[data-toggle="tooltip"]').tooltip(); });</script>
