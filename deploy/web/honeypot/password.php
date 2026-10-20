<?php
/**
 * Honeypot64 – Passwortpruefung mit k-Anonymitaet (Phase H6, Plan Abschnitt 7). Oeffentlich, ohne Menuelink; fuer
 * Eingeloggte und Gaeste gleich.
 *
 *   password.php            Seite; &lang=en Englisch
 *
 * Der Browser berechnet SHA-1 des Passworts (SubtleCrypto), schickt nur die ersten 5 Hex-Zeichen an
 * GET /api/v2/threat/passwords/range/{prefix} (api_v2_threat_passwords.php, ohne API-Key, Limit je Client-IP) und
 * vergleicht die Antwort lokal. Das Passwort und sein voller Hash verlassen nie den Browser; der Server sieht nur den
 * Praefix (rund 1 von 1 Million moeglichen Werten, viele Passwoerter teilen ihn). Kein Formularversand, kein Speichern.
 */
include("../header.php");

$hpwEn = (($_GET['lang'] ?? '') === 'en');
function hpw_t(string $de, string $en): string { global $hpwEn; return $hpwEn ? $en : $de; }
function hpw_h($s): string { return htmlspecialchars((string)$s, ENT_QUOTES, 'UTF-8'); }
/** Text fuer JavaScript (JSON, sicher im Skript-Block) */
function hpw_js($v): string { return json_encode($v, JSON_HEX_TAG | JSON_HEX_AMP | JSON_HEX_APOS | JSON_HEX_QUOT | JSON_UNESCAPED_UNICODE); }
?>
<p></p>
<div class="container">
	<div class="card mb-3"><div class="card-body">
		<a class="float-right small" href="<?php echo $hpwEn ? 'password.php' : 'password.php?lang=en'; ?>"><?php echo $hpwEn ? 'Deutsch' : 'English'; ?></a>
		<h4 class="mb-2"><i class="fa-solid fa-key text-primary"></i> Honeypot64 – <?php echo hpw_t('Passwort prüfen', 'Check a password'); ?></h4>
		<p class="mb-2"><?php echo hpw_t('Probieren Angreifer dieses Passwort aus? Die Prüfung nutzt die Passwörter, die Angreifer in den letzten 365 Tagen an Honeypot64-Sensoren eingegeben haben (nur Passwörter, die mehrere unabhängige Accounts gemeldet haben).',
			'Do attackers try this password? The check uses the passwords attackers entered at Honeypot64 sensors in the last 365 days (only passwords reported by several independent accounts).'); ?></p>
		<div class="alert alert-success small mb-0" role="note"><i class="fa-solid fa-shield-halved"></i>
			<b><?php echo hpw_t('Dein Passwort verlässt nie deinen Browser.', 'Your password never leaves your browser.'); ?></b>
			<?php echo hpw_t('Der Browser berechnet den SHA-1-Hash des Passworts und schickt nur dessen <b>ersten 5 Zeichen</b> an IPv64.net (k-Anonymität, wie bei „Have I Been Pwned“). Zurück kommt eine Liste aller bekannten Hash-Enden mit diesem Anfang – ergänzt um Zufallszeilen –, verglichen wird nur hier im Browser. IPv64.net erfährt weder das Passwort noch seinen vollständigen Hash noch das Ergebnis. Nichts wird gespeichert oder an ein Formular gesendet.',
				'Your browser computes the SHA-1 hash of the password and sends only its <b>first 5 characters</b> to IPv64.net (k-anonymity, like “Have I Been Pwned”). The answer is a list of all known hash endings with this beginning – padded with random lines – and the comparison happens only here in your browser. IPv64.net learns neither the password nor its full hash nor the result. Nothing is stored or sent with a form.'); ?>
		</div>
	</div></div>

	<div class="card mb-3"><div class="card-body">
		<noscript><div class="alert alert-warning" role="alert"><?php echo hpw_t('Die Prüfung läuft im Browser und braucht JavaScript.', 'The check runs in your browser and needs JavaScript.'); ?></div></noscript>
		<form id="hpwForm" autocomplete="off" onsubmit="return false;">
			<label for="hpwPw" class="small"><?php echo hpw_t('Passwort', 'Password'); ?></label>
			<div class="input-group mb-2">
				<input id="hpwPw" type="password" class="form-control" maxlength="256" autocomplete="off" autocapitalize="off" spellcheck="false" placeholder="<?php echo hpw_t('Passwort eingeben', 'Enter a password'); ?>">
				<div class="input-group-append">
					<button id="hpwShow" class="btn btn-outline-secondary" type="button" title="<?php echo hpw_t('anzeigen/verbergen', 'show/hide'); ?>"><i class="fa-solid fa-eye"></i></button>
					<button id="hpwGo" class="btn btn-primary" type="submit"><?php echo hpw_t('Prüfen', 'Check'); ?></button>
				</div>
			</div>
		</form>
		<div id="hpwOut" class="mt-2" aria-live="polite"></div>
		<p id="hpwSent" class="small text-muted mb-0"></p>
	</div></div>

	<div class="card mb-3"><div class="card-body small">
		<p class="mb-1"><b><?php echo hpw_t('Was heißt das Ergebnis?', 'What does the result mean?'); ?></b>
			<?php echo hpw_t('Gefunden: Angreifer probieren genau dieses Passwort – nicht mehr verwenden, auch nicht leicht abgewandelt. Nicht gefunden: Es steht nicht in unserer Liste; das sagt nichts darüber, ob es stark ist.',
				'Found: attackers try exactly this password – do not use it, not even slightly modified. Not found: it is not on our list; this says nothing about whether it is strong.'); ?></p>
		<p class="mb-1"><?php echo hpw_t('Für Programme (Login-/Registrierungsseiten):', 'For programs (login/sign-up pages):'); ?>
			<code>GET https://ipv64.net/api/v2/threat/passwords/range/&lt;<?php echo hpw_t('erste 5 Zeichen SHA-1', 'first 5 characters of SHA-1'); ?>&gt;</code>
			– <?php echo hpw_t('Antwort Text, je Zeile <code>&lt;restliche 35 Zeichen&gt;:&lt;Anzahl&gt;</code> (Anzahl 0 = Füllzeile), ohne API-Key mit Limit je IP, mit API-Key großzügiger.',
				'answer text, one line <code>&lt;remaining 35 characters&gt;:&lt;count&gt;</code> per entry (count 0 = padding), without an API key limited per IP, with an API key more generous.'); ?></p>
		<p class="mb-0"><?php echo hpw_t('Häufigste Angreifer-Passwörter als Liste:', 'Most used attacker passwords as a list:'); ?>
			<a href="/blocklists/ipv64_passwords.txt" target="_blank" rel="noopener">ipv64_passwords.txt</a> ·
			<a href="/blocklists/ipv64_passwords_sha1.txt" target="_blank" rel="noopener">ipv64_passwords_sha1.txt</a> ·
			<a href="/honeypot/stats.php<?php echo $hpwEn ? '?lang=en' : ''; ?>"><?php echo hpw_t('Statistik', 'Statistics'); ?></a></p>
	</div></div>
</div>
<script>
(function() {
	var API = '/api/v2/threat/passwords/range/';
	var T = <?php echo hpw_js(array(
		'nocrypto' => hpw_t('Dein Browser kann hier keinen SHA-1-Hash berechnen (nur über HTTPS und in aktuellen Browsern möglich).', 'Your browser cannot compute a SHA-1 hash here (only possible over HTTPS and in current browsers).'),
		'empty' => hpw_t('Bitte ein Passwort eingeben.', 'Please enter a password.'),
		'busy' => hpw_t('Prüfe …', 'Checking …'),
		'found' => hpw_t('Gefunden: Angreifer haben dieses Passwort ausprobiert (gemeldet: %n). Bitte nicht verwenden.', 'Found: attackers have tried this password (reported: %n). Please do not use it.'),
		'clean' => hpw_t('Nicht gefunden: Angreifer haben dieses Passwort an unseren Sensoren nicht ausprobiert. Das sagt nichts über seine Stärke.', 'Not found: attackers have not tried this password at our sensors. This says nothing about its strength.'),
		'limit' => hpw_t('Zu viele Abfragen. Bitte warte einen Moment und versuche es dann erneut.', 'Too many checks. Please wait a moment and try again.'),
		'error' => hpw_t('Die Prüfung ist gerade nicht verfügbar.', 'The check is currently not available.'),
		'sent' => hpw_t('An IPv64.net gesendet wurde nur: %p', 'Sent to IPv64.net was only: %p'),
	)); ?>;
	var pw = document.getElementById('hpwPw'), out = document.getElementById('hpwOut'), sent = document.getElementById('hpwSent');
	function show(cls, text) { out.innerHTML = ''; var d = document.createElement('div'); d.className = 'alert alert-' + cls + ' mb-0'; d.setAttribute('role', 'alert'); d.textContent = text; out.appendChild(d); }
	document.getElementById('hpwShow').addEventListener('click', function() { pw.type = pw.type === 'password' ? 'text' : 'password'; });
	document.getElementById('hpwForm').addEventListener('submit', function(ev) {
		ev.preventDefault();
		sent.textContent = '';
		if(!window.crypto || !window.crypto.subtle || !window.TextEncoder || !window.fetch) { show('warning', T.nocrypto); return; }
		if(pw.value === '') { show('warning', T.empty); return; }
		show('secondary', T.busy);
		crypto.subtle.digest('SHA-1', new TextEncoder().encode(pw.value)).then(function(buf) {
			var hex = Array.prototype.map.call(new Uint8Array(buf), function(b) { return ('0' + b.toString(16)).slice(-2); }).join('').toUpperCase();
			var prefix = hex.slice(0, 5), suffix = hex.slice(5);
			sent.textContent = T.sent.replace('%p', prefix);
			return fetch(API + prefix, {credentials: 'omit', cache: 'default'}).then(function(r) {
				if(r.status === 429) { throw new Error('limit'); }
				if(!r.ok) { throw new Error('error'); }
				return r.text();
			}).then(function(text) {
				var n = 0;
				text.split('\n').forEach(function(l) { var p = l.trim().split(':'); if(p.length === 2 && p[0].toUpperCase() === suffix) { n = parseInt(p[1], 10) || 0; } });
				if(n > 0) { show('danger', T.found.replace('%n', n.toLocaleString())); } else { show('success', T.clean); }
			});
		}).catch(function(e) { show('warning', e && e.message === 'limit' ? T.limit : T.error); });
	});
})();
</script>
<?php include("../footer.php"); ?>
