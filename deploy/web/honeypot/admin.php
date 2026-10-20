<?php
/**
 * Honeypot64 – Freigaben verwalten (Phase H3), nur fuer Admins (users.admin = 1, wie im Portal). Ohne Menuelink.
 *
 * - Antraege: eskalierte und offene (bestaetigte) Antraege mit Pruefangaben (gelistet/Score, Beruehrungen seit der
 *   Bestaetigung, weitere Antraege, Provider-Netz); Freigeben (Tage oder dauerhaft) oder Ablehnen, Bescheid per Mail.
 * - Freigabeliste hp_allowlist: dauerhafte/befristete Eintraege (manual, infra, cdn) anlegen und loeschen; Eintraege aus
 *   Antraegen (request) entstehen automatisch.
 * Alle Aktionen per POST mit CSRF-Token aus der Sitzung. Planung: docs/PLAN-NODE64-HONEYPOT64.md (Abschnitt 9).
 */
include("../header.php");
require_once __DIR__ . '/hp_release_lib.php';

function hpa_h($s): string { return htmlspecialchars((string)$s, ENT_QUOTES, 'UTF-8'); }
/** UTC aus der DB -> Ortszeit der Seite */
function hpa_time($utc): string { return ($utc === null OR $utc === '') ? '–' : date('d.m.Y H:i', (int)strtotime($utc . ' UTC')); }
function hpa_alert(string $type, string $text): string { return '<div class="alert alert-' . $type . '" role="alert">' . hpa_h($text) . '</div>'; }

$hpaUid = (isset($userid) AND (string)$userid !== '' AND (string)$userid !== '0') ? (int)$userid : 0;
$hpaAdmin = false;
if($hpaUid > 0) {
	try { $hpaAdmin = (string)(hpr_one($pdo, "SELECT admin FROM users WHERE id = :u", array('u' => $hpaUid))['admin'] ?? '0') === '1'; }
	catch(Throwable $e) { error_log('honeypot/admin.php: ' . $e->getMessage()); }
}
echo '<p></p><div class="container">';
if(!$hpaAdmin) {
	echo hpa_alert('danger', 'Kein Zugriff. Diese Seite ist nur für Admins.') . '</div>';
	include("../footer.php");
	exit;
}
if(empty($_SESSION['hpr_csrf'])) { $_SESSION['hpr_csrf'] = bin2hex(random_bytes(16)); }
$hpaCsrf = (string)$_SESSION['hpr_csrf'];
$now = time();
$msg = '';

try {
	// ---------------------------------------------------------------- Aktionen
	if(($_SERVER['REQUEST_METHOD'] ?? 'GET') === 'POST') {
		$act = (string)($_POST['action'] ?? '');
		$id = (int)($_POST['id'] ?? 0);
		if(!hash_equals($hpaCsrf, (string)($_POST['csrf'] ?? ''))) {
			$msg = hpa_alert('danger', 'Sitzung abgelaufen, bitte Seite neu laden.');
		} elseif($act === 'release' OR $act === 'reject') {
			$r = hpr_one($pdo, "SELECT * FROM hp_release_requests WHERE id = :id AND status IN ('open', 'escalated') AND confirmed_at IS NOT NULL", array('id' => $id));
			$note = trim(mb_substr((string)($_POST['note'] ?? ''), 0, 500));
			if($r === null) {
				$msg = hpa_alert('warning', 'Antrag nicht gefunden oder schon entschieden.');
			} elseif($act === 'release') {
				$days = (int)($_POST['days'] ?? HPR_PROTECT_DAYS);
				if($days < 0 OR $days > 3650) { $days = HPR_PROTECT_DAYS; }
				$prev = $r['note'] !== '' ? $r['note'] . "\n" : '';
				hpr_release($pdo, $r, $days === 0 ? null : $days, $hpaUid, $prev . 'Freigabe von Hand (' . ($days === 0 ? 'dauerhaft' : $days . ' Tage') . ')' . ($note !== '' ? ': ' . $note : ''));
				$x = hpr_one($pdo, "SELECT * FROM hp_release_requests WHERE id = :id", array('id' => $id));
				hpr_mail_decision($pdo, $x, 'released', $x['protected_until']);
				$msg = hpa_alert('success', 'Antrag #' . $id . ' (' . $r['ip'] . ') freigegeben.');
			} else {
				$prev = $r['note'] !== '' ? $r['note'] . "\n" : '';
				hpr_q($pdo, "UPDATE hp_release_requests SET status = 'rejected', decided_at = :t, decided_by = :by, note = :n WHERE id = :id",
					array('t' => hpr_dt($now), 'by' => $hpaUid, 'n' => mb_substr($prev . 'Abgelehnt' . ($note !== '' ? ': ' . $note : ''), 0, 2000), 'id' => $id));
				hpr_mail_decision($pdo, $r, 'rejected', null);
				$msg = hpa_alert('success', 'Antrag #' . $id . ' (' . $r['ip'] . ') abgelehnt.');
			}
		} elseif($act === 'allow_add') {
			$c = hpr_cidr((string)($_POST['cidr'] ?? ''));
			$src = (string)($_POST['source'] ?? 'manual');
			$reason = trim(mb_substr((string)($_POST['reason'] ?? ''), 0, 255));
			$days = (int)($_POST['days'] ?? 0);
			$plen = $c === null ? 0 : (int)explode('/', $c[0])[1];
			if($c === null) { $msg = hpa_alert('danger', 'Ungültiges Netz. Erwartet: IP oder CIDR, z. B. 203.0.113.0/24 oder 2001:db8::/48.'); }
			elseif((strlen($c[1]) === 4 AND $plen < 8) OR (strlen($c[1]) === 16 AND $plen < 16)) { $msg = hpa_alert('danger', 'Netz zu groß (IPv4 mindestens /8, IPv6 mindestens /16).'); }
			elseif(!in_array($src, array('manual', 'infra', 'cdn'), true)) { $msg = hpa_alert('danger', 'Ungültige Quelle.'); }
			elseif($reason === '') { $msg = hpa_alert('danger', 'Bitte einen Grund angeben.'); }
			elseif($days < 0 OR $days > 3650) { $msg = hpa_alert('danger', 'Tage: 0 (dauerhaft) bis 3650.'); }
			else {
				hpr_q($pdo, "INSERT INTO hp_allowlist (cidr, ip_start, ip_end, reason, source, `until`, created_at, created_by) VALUES (:c, UNHEX(:s), UNHEX(:e), :r, :src, :u, :t, :by)
					ON DUPLICATE KEY UPDATE reason = VALUES(reason), `until` = VALUES(`until`), created_by = VALUES(created_by)",
					array('c' => $c[0], 's' => bin2hex($c[1]), 'e' => bin2hex($c[2]), 'r' => $reason, 'src' => $src, 'u' => $days === 0 ? null : hpr_dt($now + $days * 86400), 't' => hpr_dt($now), 'by' => $hpaUid));
				$msg = hpa_alert('success', 'Freigabe ' . $c[0] . ' (' . $src . ') gespeichert.');
			}
		} elseif($act === 'allow_del') {
			$n = hpr_q($pdo, "DELETE FROM hp_allowlist WHERE id = :id", array('id' => $id))->rowCount();
			$msg = hpa_alert($n > 0 ? 'success' : 'warning', $n > 0 ? 'Freigabe gelöscht.' : 'Freigabe nicht gefunden.');
		}
	}

	// ---------------------------------------------------------------- Daten
	$open = hpr_all($pdo, "SELECT * FROM hp_release_requests WHERE status IN ('open', 'escalated') AND confirmed_at IS NOT NULL ORDER BY status = 'escalated' DESC, confirmed_at LIMIT 200");
	$unconfirmed = (int)hpr_one($pdo, "SELECT COUNT(*) c FROM hp_release_requests WHERE confirmed_at IS NULL")['c'];
	$decided = hpr_all($pdo, "SELECT id, ip, status, decided_at, decided_by, protected_until FROM hp_release_requests WHERE status IN ('released', 'rejected') ORDER BY decided_at DESC LIMIT 20");
	$allow = hpr_all($pdo, "SELECT id, cidr, reason, source, `until`, created_at, created_by FROM hp_allowlist WHERE `until` IS NULL OR `until` > :t ORDER BY source, created_at DESC LIMIT 1000", array('t' => hpr_dt($now)));
	$facts = array();
	foreach($open as $r) {
		$b = bin2hex($r['ip_bin']);
		$t = hpr_one($pdo, "SELECT COUNT(*) n, MAX(last_seen) l, COUNT(DISTINCT userid) a FROM hp_report_sources WHERE ip_bin = UNHEX(:b) AND last_seen > :c", array('b' => $b, 'c' => $r['confirmed_at']));
		$o = (int)hpr_one($pdo, "SELECT COUNT(*) c FROM hp_release_requests WHERE ip_bin = UNHEX(:b) AND id != :id AND confirmed_at IS NOT NULL AND created_at >= :d",
			array('b' => $b, 'id' => $r['id'], 'd' => hpr_dt($now - HPR_HISTORY_DAYS * 86400)))['c'];
		$mail = $r['userid'] !== null ? 'Account #' . (int)$r['userid'] . ' (' . hpr_requester_mail($pdo, $r) . ')' : $r['email'];
		$facts[$r['id']] = array('lookup' => hpr_lookup($pdo, $r['ip']), 'touch' => $t, 'others' => $o, 'provider' => hpr_provider($pdo, $r['ip_bin']), 'from' => $mail);
	}
} catch(Throwable $e) {
	error_log('honeypot/admin.php: ' . $e->getMessage());
	echo hpa_alert('danger', 'Datenbankfehler (Tabellen aus deploy/sql/honeypot_h3_release.sql eingespielt?).') . '</div>';
	include("../footer.php");
	exit;
}
?>
	<div class="card mb-3"><div class="card-body">
		<h4 class="mb-2"><i class="fa-solid fa-user-shield text-primary"></i> Honeypot64 – Freigaben (Admin)</h4>
		<p class="mb-0 small text-muted">Automatische Prüfung stündlich (bots/honeypot_release.php): 24 h nach der Bestätigung ohne neue Berührung → freigegeben, 30 Tage geschützt.
		Greift weiter an, mehrere Anträge, viele IPs vom selben Absender oder Provider-Netz → eskaliert (hier entscheiden). Unbestätigte Anträge: <?php echo $unconfirmed; ?>.</p>
	</div></div>
	<?php echo $msg; ?>

	<div class="card mb-3"><div class="card-header p-2"><i class="fa-solid fa-inbox text-primary"></i> Offene Anträge (<?php echo count($open); ?>)</div>
	<div class="card-body p-0"><div class="table-responsive">
		<table class="table table-sm mb-0 small"><thead><tr><th>#</th><th>IP</th><th>Status</th><th>Bestätigt</th><th>Absender</th><th>Begründung / Prüfung</th><th>Entscheidung</th></tr></thead><tbody>
		<?php if(empty($open)) { echo '<tr><td colspan="7" class="text-muted p-3">Keine offenen Anträge.</td></tr>'; }
		foreach($open as $r) { $f = $facts[$r['id']]; $l = $f['lookup']; ?>
			<tr>
				<td><?php echo (int)$r['id']; ?></td>
				<td><a href="ip.php?ip=<?php echo hpa_h(rawurlencode($r['ip'])); ?>" target="_blank" rel="noopener"><code><?php echo hpa_h($r['ip']); ?></code></a></td>
				<td><?php echo $r['status'] === 'escalated' ? '<span class="badge badge-warning">eskaliert</span>' : '<span class="badge badge-info">offen</span>'; ?></td>
				<td><?php echo hpa_h(hpa_time($r['confirmed_at'])); ?></td>
				<td><?php echo hpa_h($f['from']); ?></td>
				<td style="max-width:28em">
					<div class="mb-1"><?php echo nl2br(hpa_h($r['reason'])); ?></div>
					<div class="text-muted">
						<?php echo $l['listed'] ? 'gelistet, Score ' . (int)$l['score'] . ', ' . (int)$l['accounts'] . ' Accounts, ' . hpa_h(implode(', ', $l['kinds'])) : 'Status ' . hpa_h($l['status']); ?><br>
						Berührungen seit Bestätigung: <?php echo (int)$f['touch']['n']; ?><?php echo (int)$f['touch']['n'] > 0 ? ' (' . (int)$f['touch']['a'] . ' Accounts, zuletzt ' . hpa_h(hpa_time($f['touch']['l'])) . ')' : ''; ?>
						· weitere Anträge (<?php echo HPR_HISTORY_DAYS; ?> Tage): <?php echo (int)$f['others']; ?>
						· Provider-Netz: <?php echo $f['provider'] !== null ? hpa_h($f['provider']) : 'nein'; ?>
						<?php if($r['note'] !== '') { echo '<br>Notiz: ' . nl2br(hpa_h($r['note'])); } ?>
					</div>
				</td>
				<td style="min-width:16em">
					<form method="post" action="admin.php" class="form-inline mb-1">
						<input type="hidden" name="csrf" value="<?php echo hpa_h($hpaCsrf); ?>"><input type="hidden" name="id" value="<?php echo (int)$r['id']; ?>"><input type="hidden" name="action" value="release">
						<select name="days" class="form-control form-control-sm mr-1"><option value="30">30 Tage</option><option value="90">90 Tage</option><option value="365">1 Jahr</option><option value="0">dauerhaft</option></select>
						<input type="text" name="note" class="form-control form-control-sm mr-1" placeholder="Notiz" maxlength="500" style="width:7em">
						<button type="submit" class="btn btn-sm btn-success">Freigeben</button>
					</form>
					<form method="post" action="admin.php" class="form-inline">
						<input type="hidden" name="csrf" value="<?php echo hpa_h($hpaCsrf); ?>"><input type="hidden" name="id" value="<?php echo (int)$r['id']; ?>"><input type="hidden" name="action" value="reject">
						<input type="text" name="note" class="form-control form-control-sm mr-1" placeholder="Grund (intern)" maxlength="500" style="width:11.5em">
						<button type="submit" class="btn btn-sm btn-outline-danger">Ablehnen</button>
					</form>
				</td>
			</tr>
		<?php } ?>
		</tbody></table>
	</div></div></div>

	<div class="card mb-3"><div class="card-header p-2"><i class="fa-solid fa-list-check text-primary"></i> Freigabeliste (gültige Einträge: <?php echo count($allow); ?>)</div>
	<div class="card-body p-2">
		<form method="post" action="admin.php" class="form-inline mb-2">
			<input type="hidden" name="csrf" value="<?php echo hpa_h($hpaCsrf); ?>"><input type="hidden" name="action" value="allow_add">
			<input type="text" name="cidr" class="form-control form-control-sm mr-1 mb-1" placeholder="IP oder Netz (CIDR)" maxlength="49" required>
			<input type="text" name="reason" class="form-control form-control-sm mr-1 mb-1" placeholder="Grund, z. B. Partner XY" maxlength="255" required>
			<select name="source" class="form-control form-control-sm mr-1 mb-1"><option value="manual">manual (Partner, eigene)</option><option value="infra">infra (ipv64/x64)</option><option value="cdn">cdn</option></select>
			<input type="number" name="days" class="form-control form-control-sm mr-1 mb-1" value="0" min="0" max="3650" style="width:6em" title="Tage, 0 = dauerhaft">
			<button type="submit" class="btn btn-sm btn-primary mb-1">Hinzufügen</button>
		</form>
		<div class="table-responsive"><table class="table table-sm mb-0 small"><thead><tr><th>Netz</th><th>Quelle</th><th>Grund</th><th>bis</th><th>angelegt</th><th></th></tr></thead><tbody>
		<?php if(empty($allow)) { echo '<tr><td colspan="6" class="text-muted p-3">Keine Einträge.</td></tr>'; }
		foreach($allow as $a) { ?>
			<tr><td><code><?php echo hpa_h($a['cidr']); ?></code></td><td><?php echo hpa_h($a['source']); ?></td><td><?php echo hpa_h($a['reason']); ?></td>
			<td><?php echo $a['until'] === null ? 'dauerhaft' : hpa_h(hpa_time($a['until'])); ?></td>
			<td><?php echo hpa_h(hpa_time($a['created_at'])); ?><?php echo $a['created_by'] !== null ? ' <span class="text-muted">#' . (int)$a['created_by'] . '</span>' : ''; ?></td>
			<td><form method="post" action="admin.php" class="m-0" onsubmit="return confirm('Freigabe <?php echo hpa_h($a['cidr']); ?> löschen?');">
				<input type="hidden" name="csrf" value="<?php echo hpa_h($hpaCsrf); ?>"><input type="hidden" name="action" value="allow_del"><input type="hidden" name="id" value="<?php echo (int)$a['id']; ?>">
				<button type="submit" class="btn btn-sm btn-link text-danger p-0">löschen</button></form></td></tr>
		<?php } ?>
		</tbody></table></div>
	</div></div>

	<div class="card mb-3"><div class="card-header p-2">Zuletzt entschieden</div>
	<div class="card-body p-0"><div class="table-responsive">
		<table class="table table-sm mb-0 small"><thead><tr><th>#</th><th>IP</th><th>Ergebnis</th><th>entschieden</th><th>von</th><th>geschützt bis</th></tr></thead><tbody>
		<?php if(empty($decided)) { echo '<tr><td colspan="6" class="text-muted p-3">Noch nichts entschieden.</td></tr>'; }
		foreach($decided as $d) { ?>
			<tr><td><?php echo (int)$d['id']; ?></td><td><code><?php echo hpa_h($d['ip']); ?></code></td>
			<td><?php echo $d['status'] === 'released' ? '<span class="badge badge-success">freigegeben</span>' : '<span class="badge badge-danger">abgelehnt</span>'; ?></td>
			<td><?php echo hpa_h(hpa_time($d['decided_at'])); ?></td><td><?php echo $d['decided_by'] === null ? 'automatisch' : '#' . (int)$d['decided_by']; ?></td>
			<td><?php echo $d['status'] === 'released' ? ($d['protected_until'] === null ? 'dauerhaft' : hpa_h(hpa_time($d['protected_until']))) : '–'; ?></td></tr>
		<?php } ?>
		</tbody></table>
	</div></div></div>
</div>
<?php include("../footer.php"); ?>
