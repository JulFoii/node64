<?php
/**
 * IPv64.net – Navigationsreiter „Node64 (Admin)“: alle Seiten des Node64-Projekts zum Durchklicken, nur fuer Admins
 * (users.admin = 1, wie im Portal). Wird von header.php innerhalb der Navigationsliste eingebunden:
 *     <?php include __DIR__ . '/admin_project_nav.php'; ?>
 * Ohne Admin-Recht gibt die Datei nichts aus.
 */
if (!isset($account) || !is_array($account) || (string)($account['admin'] ?? '0') !== '1') {
	return;
}
$n64nav = array(
	'Node64' => array(
		array('fa-cube', 'Node64 – Vorstellungsseite', 'https://ipv64.net/node64.php'),
		array('fa-network-wired', 'Meine Nodes (Übersicht)', 'https://ipv64.net/nodes'),
		array('fa-link', 'Node verknüpfen (Code)', 'https://ipv64.net/link'),
		array('fa-book', 'node64.de (Doku)', 'https://node64.de', true),
	),
	'Healthchecks 2.0' => array(
		array('fa-heart-pulse', 'Übersicht', 'https://ipv64.net/healthchecks2/'),
		array('fa-plus', 'Neuer Check', 'https://ipv64.net/healthchecks2/edit'),
		array('fa-triangle-exclamation', 'Störungen', 'https://ipv64.net/healthchecks2/incidents'),
		array('fa-screwdriver-wrench', 'Wartungsfenster', 'https://ipv64.net/healthchecks2/maintenance'),
		array('fa-right-left', 'Umhängen (Ausführungsort)', 'https://ipv64.net/healthchecks2/move'),
		array('fa-bell', 'Benachrichtigungskanäle', 'https://ipv64.net/notifications'),
	),
	'CDN64' => array(
		array('fa-globe', 'CDN64 (Namen, Modus 3, Portmapper)', 'https://ipv64.net/cdn64'),
	),
	'Honeypot64' => array(
		array('fa-bug', 'Meine Sensoren', 'https://ipv64.net/honeypot/'),
		array('fa-chart-column', 'Statistik', 'https://ipv64.net/honeypot/stats'),
		array('fa-magnifying-glass', 'IP-Auskunft', 'https://ipv64.net/honeypot/ip'),
		array('fa-tower-broadcast', 'Frühwarnung', 'https://ipv64.net/honeypot/watch'),
		array('fa-key', 'Passwort-Check', 'https://ipv64.net/honeypot/password'),
		array('fa-ticket', 'Listen-Token (Live-Blockliste)', 'https://ipv64.net/honeypot/token'),
		array('fa-user-shield', 'Freigaben verwalten (Admin)', 'https://ipv64.net/honeypot/admin'),
	),
	'Blocklisten & API' => array(
		array('fa-road-barrier', 'IPv64 Blocklists', 'https://ipv64.net/v64_blocklists'),
		array('fa-book-open', 'Blocklisten-Integration', 'https://ipv64.net/v64_blocklist_integration_guide'),
		array('fa-shield', 'IPv64 Secure', 'https://ipv64.net/v64_secure'),
		array('fa-code', 'API v2 Doku', 'https://ipv64.net/api_v2_docs'),
	),
	'Mails' => array(
		array('fa-envelope-open-text', 'Wochenbericht – Vorschau und Testmail', 'https://ipv64.net/weekly_report_preview.php'),
	),
);
?>
			<li class="nav-item dropdown text-dark">
				<a class="nav-link dropdown-toggle text-danger" href="#" id="n64admin_dropdown" data-toggle="dropdown" aria-haspopup="true" aria-expanded="false" title="Nur für Admins sichtbar"><i class="fa-solid fa-flask fa-sm"></i> Node64</a>
				<div class="dropdown-menu" aria-labelledby="n64admin_dropdown" style="max-height:80vh;overflow-y:auto">
<?php $n64first = true; foreach ($n64nav as $n64group => $n64items) { ?>
					<?php if (!$n64first) { ?><div class="dropdown-divider"></div><?php } $n64first = false; ?>
					<h6 class="dropdown-header"><?php echo htmlspecialchars($n64group, ENT_QUOTES, 'UTF-8'); ?></h6>
<?php foreach ($n64items as $n64i) { ?>
					<a class="dropdown-item" href="<?php echo htmlspecialchars($n64i[2], ENT_QUOTES, 'UTF-8'); ?>"<?php if (!empty($n64i[3])) { ?> target="_blank" rel="noopener"<?php } ?>><i class="fa-solid <?php echo $n64i[0]; ?> fa-sm fa-fw"></i> <?php echo htmlspecialchars($n64i[1], ENT_QUOTES, 'UTF-8'); ?></a>
<?php } } ?>
				</div>
			</li>
<?php unset($n64nav, $n64group, $n64items, $n64i, $n64first); ?>
