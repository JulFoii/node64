<?php
/**
 * Honeypot64 – Live-Karte (oeffentlich, verlinkt aus der Statistik und "Secure"). Boegen vom Land der Angreifer zum
 * Land des Sensors auf einer flachen Weltkarte, darunter die letzten Angriffe. Daten: live.json (alle 2 Minuten von
 * bots/honeypot_live.php geschrieben, statisch – die Seite selbst fragt keine Datenbank), Karte: worldmap.json
 * (Natural Earth 1:110m, aus Node64 erzeugt). Quellen nur maskiert, Ziel nur als Land, keine Zugangsdaten.
 *
 *   live.php            Deutsch
 *   live.php?lang=en    Englisch
 */
include("../header.php");
$hlEn = (($_GET['lang'] ?? '') === 'en');
function hl_t(string $de, string $en): string { global $hlEn; return $hlEn ? $en : $de; }
?>
<p></p>
<div class="container">
	<div class="card mb-3"><div class="card-body">
		<a class="float-right small" href="<?php echo $hlEn ? 'live.php' : 'live.php?lang=en'; ?>"><?php echo $hlEn ? 'Deutsch' : 'English'; ?></a>
		<h4 class="mb-2"><i class="fa-solid fa-earth-europe text-primary"></i> Honeypot64 – <?php echo hl_t('Live-Karte', 'Live map'); ?>
			<span class="badge badge-danger align-middle small" id="hlLiveBadge">LIVE</span></h4>
		<p class="mb-1"><?php echo hl_t('Angriffe auf die Honeypot64-Sensoren der Community, vom Land des Angreifers zum Land des Sensors. Die Sensoren melden alle 10 Minuten – die Karte zeigt die letzte Stunde zeitversetzt und spielt sie fortlaufend ab; ist gerade nichts Neues da, werden ältere Angriffe blasser wiederholt.',
			'Attacks on the community\'s Honeypot64 sensors, from the attacker\'s country to the sensor\'s country. Sensors report every 10 minutes – the map shows the last hour with a delay and plays it continuously; when nothing new comes in, older attacks are replayed fainter.'); ?></p>
		<p class="mb-0 small text-muted"><?php echo hl_t('Angreifer nur gekürzt (IPv4 /24, IPv6 /48), Sensoren nur als Land, keine Zugangsdaten. Mehr Zahlen:', 'Attackers only shortened (IPv4 /24, IPv6 /48), sensors only as country, no credentials. More numbers:'); ?>
			<a href="stats.php<?php echo $hlEn ? '?lang=en' : ''; ?>"><?php echo hl_t('Statistik', 'Statistics'); ?></a> · <?php echo hl_t('IP prüfen:', 'Check an IP:'); ?> <a href="ip.php<?php echo $hlEn ? '?lang=en' : ''; ?>">ip.php</a></p>
	</div></div>

	<div class="row">
		<?php foreach(array(array('events', hl_t('Angriffe (60 min)', 'Attacks (60 min)'), 'fa-bug', 'primary'), array('sources', hl_t('Angreifer-Netze', 'Attacker networks'), 'fa-network-wired', 'danger'),
			array('targets', hl_t('Länder mit Sensoren', 'Countries with sensors'), 'fa-satellite-dish', 'success'), array('top', hl_t('Häufigstes Herkunftsland', 'Top source country'), 'fa-flag', 'info')) as [$k, $label, $icon, $color]) { ?>
		<div class="col-6 col-md pb-3"><div class="card bg-light h-100" style="border-left:4px solid var(--<?php echo $color; ?>)"><div class="card-body p-2"><i class="fa-solid <?php echo $icon; ?> fa-2xl float-right pt-4 text-<?php echo $color; ?>"></i>
			<p class="lead m-0"><?php echo htmlspecialchars($label); ?></p><p class="card-text h3" data-hl-stat="<?php echo $k; ?>">–</p>
		</div></div></div>
		<?php } ?>
	</div>

	<div class="card mb-3">
		<div class="card-header p-2 d-flex flex-wrap align-items-center" style="gap:.6rem">
			<span><i class="fa-solid fa-map text-primary"></i> <?php echo hl_t('Angriffe der letzten Stunde', 'Attacks of the last hour'); ?></span>
			<span class="small d-flex flex-wrap align-items-center" style="gap:.6rem">
				<span><span class="hl-sw hl-g-login"></span> <?php echo hl_t('Login', 'Login'); ?></span>
				<span><span class="hl-sw hl-g-exploit"></span> <?php echo hl_t('Exploit', 'Exploit'); ?></span>
				<span><span class="hl-sw hl-g-scan"></span> <?php echo hl_t('Scan', 'Scan'); ?></span>
				<span><span class="hl-sw hl-g-probe"></span> <?php echo hl_t('Sondierung', 'Probe'); ?></span>
				<span><span class="hl-sw hl-g-log"></span> <?php echo hl_t('aus Logs', 'from logs'); ?></span>
			</span>
			<button type="button" class="btn btn-sm btn-outline-danger py-0 ml-auto" id="hlPause"><i class="fa-solid fa-pause"></i> <?php echo hl_t('Anhalten', 'Pause'); ?></button>
		</div>
		<div class="card-body p-2">
			<svg id="hlMap" class="hl-map" viewBox="0 0 1000 436" role="img" aria-label="<?php echo hl_t('Weltkarte mit Angriffen', 'World map with attacks'); ?>"><g id="hlLand"></g><g id="hlArcs"></g></svg>
			<div class="small text-muted" id="hlUpdated"></div>
		</div>
	</div>

	<div class="card mb-3">
		<div class="card-header p-2"><i class="fa-solid fa-list text-primary"></i> <?php echo hl_t('Letzte Angriffe (echte Einträge, neueste zuerst)', 'Latest attacks (real entries, newest first)'); ?></div>
		<div class="table-responsive"><table class="table table-sm table-striped mb-0 small">
			<thead><tr><th><?php echo hl_t('Zeit', 'Time'); ?></th><th><?php echo hl_t('Angreifer', 'Attacker'); ?></th><th><?php echo hl_t('Art', 'Kind'); ?></th><th><?php echo hl_t('Dienst', 'Service'); ?></th><th><?php echo hl_t('Ziel', 'Target'); ?></th><th class="text-right"><?php echo hl_t('Anzahl', 'Count'); ?></th></tr></thead>
			<tbody id="hlTable"><tr><td colspan="6" class="text-muted"><?php echo hl_t('Lade …', 'Loading …'); ?></td></tr></tbody>
		</table></div>
	</div>
</div>
<style>
	.hl-map { display: block; width: 100%; height: auto; background: #f4f7fa; border-radius: .25rem; }
	.hl-map #hlLand path { fill: #e3e6ea; stroke: #fff; stroke-width: .4; stroke-linejoin: round; }
	/* hell gehalten, damit die Boegen darauf sichtbar bleiben */
	.hl-map #hlLand path.hl-m1 { fill: #fde6cf; } .hl-map #hlLand path.hl-m2 { fill: #fdd3ab; } .hl-map #hlLand path.hl-m3 { fill: #fdbd86; }
	.hl-map #hlLand path.hl-m4 { fill: #fca562; } .hl-map #hlLand path.hl-m5 { fill: #f68c45; }
	.hl-map #hlLand path:hover { filter: brightness(1.1); stroke: #333; stroke-width: .8; }
	.hl-map path.hl-arc { fill: none; stroke-width: 2.4; stroke-linecap: round; filter: drop-shadow(0 0 1.5px rgba(0,0,0,.35)); }
	.hl-map path.hl-replay { stroke-width: 1.8; stroke-opacity: .7; }
	.hl-map circle.hl-src { stroke: #fff; stroke-width: .6; }
	.hl-map .hl-dst { fill: none; stroke: #dc3545; stroke-width: 1; transform-box: fill-box; transform-origin: center; animation: hlPulse 2s ease-out infinite; }
	@keyframes hlPulse { from { transform: scale(.6); opacity: .9; } to { transform: scale(3); opacity: 0; } }
	@media (prefers-reduced-motion: reduce) { .hl-map .hl-dst { animation: none; } }
	.hl-g-login { stroke: #dc3545; fill: #dc3545; } .hl-g-exploit { stroke: #fd7e14; fill: #fd7e14; } .hl-g-scan { stroke: #17a2b8; fill: #17a2b8; }
	.hl-g-probe { stroke: #6c757d; fill: #6c757d; } .hl-g-log { stroke: #007bff; fill: #007bff; }
	.hl-sw { display: inline-block; width: .7rem; height: .7rem; border-radius: 50%; vertical-align: -.05rem; }
	.hl-sw.hl-g-login { background: #dc3545; } .hl-sw.hl-g-exploit { background: #fd7e14; } .hl-sw.hl-g-scan { background: #17a2b8; }
	.hl-sw.hl-g-probe { background: #6c757d; } .hl-sw.hl-g-log { background: #007bff; }
	#hlTable tr.hl-new { animation: hlNew 2s ease-out; }
	@keyframes hlNew { from { background: #fff3cd; } to { background: transparent; } }
</style>
<script>window.HL_LANG = <?php echo json_encode($hlEn ? 'en' : 'de'); ?>; window.HL_T = <?php echo json_encode(array(
	'replay' => hl_t('Wiederholung', 'replay'), 'updated' => hl_t('Stand der Daten: {time} · neue Daten alle 2 Minuten', 'Data as of {time} · new data every 2 minutes'),
	'empty' => hl_t('In der letzten Stunde keine Angriffe gemeldet.', 'No attacks reported in the last hour.'), 'pause' => hl_t('Anhalten', 'Pause'), 'play' => hl_t('Weiter', 'Resume'),
	'unavailable' => hl_t('Die Live-Daten sind gerade nicht verfügbar.', 'Live data is currently not available.'), 'attacks' => hl_t('Angriffe', 'attacks')), JSON_UNESCAPED_UNICODE); ?>;</script>
<script src="live.js?v=1"></script>
<?php include("../footer.php"); ?>
