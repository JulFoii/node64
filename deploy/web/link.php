<?php
/**
 * Healthchecks 2.0: Node64 verknuepfen (Device-Code). Bewusst ohne Menuelink; nur per URL erreichbar.
 * Ablauf: die Node zeigt einen Code, der Nutzer gibt ihn hier ein und waehlt Standort und Fernverwaltung;
 * danach holt sich die Node ihren Token selbst beim hub ab (Sync-Plan 3.2).
 */
ob_start(); // header.php gibt HTML aus; hc2_redirect()/hc2_json() verwerfen es
include("header.php");

if ($userid == "") { echo '<div class="container"><div class="alert alert-warning mt-3">Bitte zuerst anmelden.</div></div>'; include("footer.php"); exit; }
if (empty($_SESSION['hc2_csrf'])) { $_SESSION['hc2_csrf'] = bin2hex(random_bytes(16)); }

$msg = ''; $ok = false;
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
	if (!hash_equals($_SESSION['hc2_csrf'], (string)($_POST['_csrf'] ?? ''))) {
		$msg = 'Ungültige Anfrage, bitte Seite neu laden.';
	} else {
		$code = strtoupper(preg_replace('/[^A-Za-z0-9]/', '', (string)($_POST['code'] ?? '')));
		$location = mb_substr(trim((string)($_POST['location'] ?? '')), 0, 100);
		$remote = in_array($_POST['remote_mgmt'] ?? '', array('off', 'read', 'full'), true) ? $_POST['remote_mgmt'] : 'read';
		if (strlen($code) !== 8) {
			$msg = 'Der Code hat 8 Zeichen (ohne Bindestrich).';
		} else {
			try {
				$hc = hc2_pdo();
				$st = $hc->prepare("UPDATE hc2_link_codes SET userid = :u, location = :l, remote_mgmt = :r WHERE code = :c AND userid IS NULL AND consumed_at IS NULL AND expires_at > UTC_TIMESTAMP(3)");
				$st->execute(array('u' => (int)$userid, 'l' => $location, 'r' => $remote, 'c' => $code));
				if ($st->rowCount() === 1) {
					$ok = true;
					$msg = 'Code angenommen. Die Node verbindet sich jetzt von selbst – das dauert bis zu 10 Sekunden.';
				} else {
					$msg = 'Code unbekannt, abgelaufen oder schon verwendet. In der Node einen neuen Code anfordern.';
				}
			} catch (Throwable $e) {
				error_log('link.php: ' . $e->getMessage());
				$msg = 'Verknüpfung derzeit nicht möglich.';
			}
		}
	}
}
?>
<div class="container">
	<div class="row">
		<div class="col-12 col-xl-6">
			<div class="card shadow-sm mt-3">
				<div class="card-header p-2"><i class="fa-solid fa-link"></i> Node64 verknüpfen</div>
				<div class="card-body">
					<?php if ($msg !== '') { echo '<div class="alert ' . ($ok ? 'alert-success' : 'alert-danger') . '">' . htmlspecialchars($msg) . '</div>'; } ?>
					<p>Gib den Code ein, den deine Node unter <em>ipv64-Verknüpfung</em> anzeigt. Danach erscheint die Node unter deinen Nodes und ihre Checks im Portal.</p>
					<form method="post">
						<input type="hidden" name="_csrf" value="<?php echo htmlspecialchars($_SESSION['hc2_csrf']); ?>">
						<div class="form-group">
							<label for="code">Code</label>
							<input class="form-control form-control-lg text-monospace" id="code" name="code" placeholder="ABCD-EFGH" maxlength="9" autocomplete="off" required>
						</div>
						<div class="form-group">
							<label for="location">Standort (frei, z. B. Zuhause, Büro)</label>
							<input class="form-control" id="location" name="location" maxlength="100">
						</div>
						<div class="form-group">
							<label for="remote_mgmt">Fernverwaltung aus dem Portal</label>
							<select class="form-control" id="remote_mgmt" name="remote_mgmt">
								<option value="read" selected>Nur lesen und Testläufe (empfohlen)</option>
								<option value="full">Vollständig (Checks anlegen, pausieren, prüfen)</option>
								<option value="off">Aus (Node sendet nur, nimmt keine Befehle an)</option>
							</select>
						</div>
						<p class="small text-muted">Hinweis: Nach der Verknüpfung überträgt die Node ihre Konfiguration und Messergebnisse an ipv64.net – auch Ziele in deinem Heimnetz. Du kannst die Verknüpfung in der Node jederzeit trennen.</p>
						<button class="btn btn-primary" type="submit">Verknüpfen</button>
						<a class="btn btn-outline-secondary" href="nodes.php">Meine Nodes</a>
					</form>
				</div>
			</div>
		</div>
	</div>
</div>
<?php include("footer.php"); ?>
