<?php
/**
 * IPv64.net – Karte „E-Mails von IPv64.net“ in den Kontoeinstellungen: Wochenbericht (an/aus, Sprache) und Newsletter.
 * Wird von account.php im Bereich ?accountsettings eingebunden (eigene Zeile, z. B. vor „Data privacy“):
 *     <?php include __DIR__ . '/account_mail_prefs.php'; ?>
 * Erwartet $pdo und $account aus header.php. Speichert selbst (POST mit mail_prefs=1, eigenes CSRF-Token).
 */
if (!isset($account) || !is_array($account) || empty($account['id'])) { return; }
if (empty($_SESSION['mail_prefs_csrf'])) { $_SESSION['mail_prefs_csrf'] = bin2hex(random_bytes(16)); }
$mpMsg = '';
if (($_POST['mail_prefs'] ?? '') === '1') {
	if (hash_equals($_SESSION['mail_prefs_csrf'], (string)($_POST['mail_prefs_csrf'] ?? ''))) {
		$mpWeekly = !empty($_POST['weekly_report']) ? 1 : 0;
		$mpNews = !empty($_POST['newsletter']) ? 1 : 0;
		$mpLang = ($_POST['weekly_report_lang'] ?? 'de') === 'en' ? 'en' : 'de';
		$pdo->prepare("UPDATE users SET weekly_report = :w, weekly_report_lang = :l, newsletter = :n WHERE id = :u")
			->execute(array('w' => $mpWeekly, 'l' => $mpLang, 'n' => $mpNews, 'u' => (int)$account['id']));
		$account['weekly_report'] = $mpWeekly; $account['weekly_report_lang'] = $mpLang; $account['newsletter'] = $mpNews;
		if (function_exists('add_log')) { add_log($pdo, (int)$account['id'], '0', 'Account', 'E-mail settings: weekly report ' . ($mpWeekly ? 'on' : 'off') . ' (' . $mpLang . '), newsletter ' . ($mpNews ? 'on' : 'off') . '.'); }
		$mpMsg = '<div class="alert alert-success py-2 small">Gespeichert.</div>';
	} else {
		$mpMsg = '<div class="alert alert-danger py-2 small">Sitzung abgelaufen, bitte noch einmal speichern.</div>';
	}
}
$mpW = (int)($account['weekly_report'] ?? 1) === 1;
$mpN = (int)($account['newsletter'] ?? 0) === 1;
$mpL = ($account['weekly_report_lang'] ?? 'de') === 'en' ? 'en' : 'de';
?>
			<div class="row" id="mail-prefs">
				<div class="col-12">
					<div class="card shadow-sm">
				  <div class="card-header">
				  <i class="fa-solid fa-envelope-open-text"></i>
					E-Mails von IPv64.net
				  </div>
				  <div class="card-body">
					<?php echo $mpMsg; ?>
					<form action="?accountsettings#mail-prefs" method="post">
						<input type="hidden" name="mail_prefs" value="1">
						<input type="hidden" name="mail_prefs_csrf" value="<?php echo htmlspecialchars($_SESSION['mail_prefs_csrf'], ENT_QUOTES, 'UTF-8'); ?>">
						<div class="custom-control custom-switch mb-1">
							<input type="checkbox" class="custom-control-input" id="mp_weekly" name="weekly_report" value="1"<?php echo $mpW ? ' checked' : ''; ?>>
							<label class="custom-control-label" for="mp_weekly"><b>Wochenbericht</b> – einmal pro Woche eine Übersicht über deine Domains, Healthchecks, CDN64 und deinen Cloud Router</label>
						</div>
						<div class="form-inline mb-3 ml-4">
							<label class="small text-muted mr-2" for="mp_lang">Sprache</label>
							<select class="custom-select custom-select-sm" id="mp_lang" name="weekly_report_lang">
								<option value="de"<?php echo $mpL === 'de' ? ' selected' : ''; ?>>Deutsch</option>
								<option value="en"<?php echo $mpL === 'en' ? ' selected' : ''; ?>>English</option>
							</select>
						</div>
						<div class="custom-control custom-switch mb-3">
							<input type="checkbox" class="custom-control-input" id="mp_news" name="newsletter" value="1"<?php echo $mpN ? ' checked' : ''; ?>>
							<label class="custom-control-label" for="mp_news"><b>Newsletter</b> – Neuigkeiten, neue Funktionen und wichtige Hinweise zu IPv64.net</label>
						</div>
						<button type="submit" class="btn btn-primary btn-sm float-right">Speichern</button>
						<small class="text-muted">Benachrichtigungen zu Störungen und Sicherheit bekommst du unabhängig davon.</small>
					</form>
				  </div>
					</div>
				</div>
			</div>
			<p></p>
<?php unset($mpMsg, $mpW, $mpN, $mpL, $mpWeekly, $mpNews, $mpLang); ?>
