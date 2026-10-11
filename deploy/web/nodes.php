<?php
/**
 * Healthchecks 2.0: Meine Nodes (Liste, Token widerrufen). Bewusst ohne Menuelink; nur per URL erreichbar.
 */
include("header.php");

if ($userid == "") { echo '<div class="container"><div class="alert alert-warning mt-3">Bitte zuerst anmelden.</div></div>'; include("footer.php"); exit; }
if (empty($_SESSION['hc2_csrf'])) { $_SESSION['hc2_csrf'] = bin2hex(random_bytes(16)); }

$msg = '';
try {
	$hc = hc2_pdo();
	if ($_SERVER['REQUEST_METHOD'] === 'POST' && hash_equals($_SESSION['hc2_csrf'], (string)($_POST['_csrf'] ?? ''))) {
		$nid = preg_replace('/[^A-Za-z0-9_-]/', '', (string)($_POST['node_id'] ?? ''));
		$action = (string)($_POST['action'] ?? '');
		if ($nid !== '') {
			$own = $hc->prepare("SELECT node_id FROM hc2_nodes WHERE node_id = :n AND userid = :u");
			$own->execute(array('n' => $nid, 'u' => (int)$userid));
			if ($own->fetchColumn()) {
				if ($action === 'revoke') {
					$hc->prepare("UPDATE hc2_node_tokens SET revoked_at = UTC_TIMESTAMP(3) WHERE node_id = :n AND revoked_at IS NULL")->execute(array('n' => $nid));
					$hc->prepare("UPDATE hc2_nodes SET revoked_at = UTC_TIMESTAMP(3), online = 0 WHERE node_id = :n")->execute(array('n' => $nid));
					$hc->prepare("UPDATE hc2_checks SET execution = 'online', updated_at = UTC_TIMESTAMP(3) WHERE node_id = :n AND deleted_at IS NULL AND execution IN ('local','both')")->execute(array('n' => $nid));
					hc2_log_change((int)$userid, 'node', $nid, 'delete', 'portal');
					$msg = 'Token widerrufen. Die Node läuft standalone weiter; ihre Checks bleiben als Online-Checks erhalten.';
				} elseif ($action === 'command') {
					$name = in_array($_POST['cmd'] ?? '', array('run_check', 'repair'), true) ? $_POST['cmd'] : '';
					$token = preg_replace('/[^A-Za-z0-9]/', '', (string)($_POST['token'] ?? ''));
					if ($name !== '') {
						$hc->prepare("INSERT INTO hc2_commands (node_id, name, args, created_at) VALUES (:n, :c, :a, UTC_TIMESTAMP(3))")
							->execute(array('n' => $nid, 'c' => $name, 'a' => json_encode(array('token' => $token))));
						$msg = 'Befehl an die Node gegeben.';
					}
				}
			}
		}
	}
	$st = $hc->prepare("SELECT node_id, name, location, version, timezone, modules, remote_mgmt, last_seen, last_sync, outbox_size, conflicts, online, node, created_at, revoked_at,
		(SELECT COUNT(*) FROM hc2_checks c WHERE c.node_id = n.node_id AND c.deleted_at IS NULL AND c.execution IN ('local','both')) AS checks
		FROM hc2_nodes n WHERE userid = :u ORDER BY created_at DESC");
	$st->execute(array('u' => (int)$userid));
	$nodes = $st->fetchAll(PDO::FETCH_ASSOC);
} catch (Throwable $e) {
	error_log('nodes.php: ' . $e->getMessage());
	$nodes = array(); $msg = 'Nodes derzeit nicht abrufbar.';
}
function hc2_ago($utc) {
	if (!$utc) { return '–'; }
	$t = new DateTime($utc, new DateTimeZone('UTC')); $t->setTimezone(new DateTimeZone('Europe/Berlin'));
	return $t->format('d.m.Y H:i:s');
}
?>
<div class="container">
	<div class="row">
		<div class="col-12">
			<div class="card shadow-sm mt-3">
				<div class="card-header p-2 d-flex justify-content-between align-items-center">
					<span><i class="fa-solid fa-server"></i> Meine Nodes</span>
					<a class="btn btn-sm btn-primary" href="link.php">Node verknüpfen</a>
				</div>
				<div class="card-body">
					<?php if ($msg !== '') { echo '<div class="alert alert-info">' . htmlspecialchars($msg) . '</div>'; } ?>
					<?php if (!$nodes) { echo '<p class="text-muted">Noch keine Node verknüpft. In der Node unter <em>ipv64-Verknüpfung</em> einen Code anfordern und unter <a href="link.php">Node verknüpfen</a> eingeben.</p>'; } else { ?>
					<div class="table-responsive"><table class="table table-sm">
						<thead><tr><th>Name</th><th>Standort</th><th>Status</th><th>Version</th><th>Letzter Abgleich</th><th>Checks</th><th>Ausstehend</th><th>Fernverwaltung</th><th></th></tr></thead>
						<tbody>
						<?php foreach ($nodes as $n) { $revoked = !empty($n['revoked_at']); ?>
						<tr<?php echo $revoked ? ' class="text-muted"' : ''; ?>>
							<td><?php echo htmlspecialchars($n['name']); ?><br><small class="text-muted"><?php echo htmlspecialchars($n['node_id']); ?></small></td>
							<td><?php echo htmlspecialchars($n['location']); ?></td>
							<td><?php if ($revoked) { echo '<span class="badge badge-secondary">getrennt</span>'; } elseif ((int)$n['online'] === 1) { echo '<span class="badge badge-success">online</span> <small class="text-muted">' . htmlspecialchars($n['node']) . '</small>'; } else { echo '<span class="badge badge-warning">offline</span><br><small class="text-muted">seit ' . hc2_ago($n['last_seen']) . '</small>'; } ?></td>
							<td><?php echo htmlspecialchars($n['version']); ?></td>
							<td><?php echo hc2_ago($n['last_sync']); ?></td>
							<td><?php echo (int)$n['checks']; ?></td>
							<td><?php echo (int)$n['outbox_size']; ?><?php if ((int)$n['conflicts'] > 0) { echo ' <span class="badge badge-danger">' . (int)$n['conflicts'] . ' Konflikte</span>'; } ?></td>
							<td><?php echo htmlspecialchars($n['remote_mgmt']); ?></td>
							<td class="text-nowrap">
								<?php if (!$revoked) { ?>
								<form method="post" class="d-inline" onsubmit="return confirm('Token widerrufen? Die Node läuft danach standalone, ihre Checks bleiben als Online-Checks.');">
									<input type="hidden" name="_csrf" value="<?php echo htmlspecialchars($_SESSION['hc2_csrf']); ?>">
									<input type="hidden" name="node_id" value="<?php echo htmlspecialchars($n['node_id']); ?>">
									<input type="hidden" name="action" value="revoke">
									<button class="btn btn-sm btn-outline-danger" type="submit">Token widerrufen</button>
								</form>
								<form method="post" class="d-inline">
									<input type="hidden" name="_csrf" value="<?php echo htmlspecialchars($_SESSION['hc2_csrf']); ?>">
									<input type="hidden" name="node_id" value="<?php echo htmlspecialchars($n['node_id']); ?>">
									<input type="hidden" name="action" value="command"><input type="hidden" name="cmd" value="repair">
									<button class="btn btn-sm btn-outline-secondary" type="submit" title="Vollabgleich anstoßen">Abgleich</button>
								</form>
								<?php } ?>
							</td>
						</tr>
						<?php } ?>
						</tbody>
					</table></div>
					<?php } ?>
				</div>
			</div>
		</div>
	</div>
</div>
<?php include("footer.php"); ?>
