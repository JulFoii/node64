<?php
/**
 * IPv64.net – Werbeseite fuer Node64 (offizieller Homelab-Container von ipv64.net).
 * Oeffentlich, ohne Login und ohne DB. Inhalte nur aus node64.de (node64_webseite); Bilder unter /img/node64/.
 *   node64.php            Deutsch
 *   node64.php?lang=en    Englisch
 * Hinweis: /node64 ist auf dem Server ein Ordner (latest.json) – deshalb immer auf /node64.php verlinken.
 */
include("header.php");

$n64En = (($_GET['lang'] ?? '') === 'en');
function n64_t(string $de, string $en): string { global $n64En; return $n64En ? $en : $de; }
/** Link auf node64.de in der passenden Sprache */
function n64_url(string $path = ''): string { global $n64En; return 'https://node64.de/' . ($n64En ? 'en/' : '') . $path; }
/** Bildschirmfoto in hell und dunkel (passend zum Darkmode der Seite; das ausgeblendete wird mit loading=lazy nicht geladen) */
function n64_shot(string $name, string $alt): string {
	$a = htmlspecialchars($alt, ENT_QUOTES, 'UTF-8');
	return '<img src="/img/node64/shot_' . $name . '_light.webp" alt="' . $a . '" class="img-fluid rounded border n64-light" loading="lazy">'
		. '<img src="/img/node64/shot_' . $name . '_dark.webp" alt="' . $a . '" class="img-fluid rounded border n64-dark" loading="lazy">';
}
$n64Modules = array(
	array('fa-heart-pulse', 'text-danger', n64_t('Healthchecks & Statusseiten', 'Health checks & status pages'), 'healthchecks/',
		n64_t('Webseiten, Server, Ports, Zertifikate, Cronjobs und Docker-Container überwachen – lokal und von außen über ipv64.net. Dazu öffentliche Statusseiten mit Tagesbalken.',
			'Monitor websites, servers, ports, certificates, cron jobs and Docker containers – locally and from outside via ipv64.net. Plus public status pages with daily bars.')),
	array('fa-sitemap', 'text-primary', 'PROXY64', 'cdn64/',
		n64_t('Reverse-Proxy mit Let\'s Encrypt, HTTP/3, Zugriffslisten, Ländersperre und den Blocklisten von ipv64 – die Nginx-Proxy-Manager-Alternative ohne nginx.',
			'Reverse proxy with Let\'s Encrypt, HTTP/3, access lists, country blocking and the ipv64 blocklists – the Nginx Proxy Manager alternative without nginx.')),
	array('fa-cloud-arrow-up', 'text-info', 'CDN64', 'cdn64-tunnel/',
		n64_t('Dienste aus dem Heimnetz ohne Portfreigabe ins Internet bringen – über Edge-Server in Deutschland, auch hinter DS-Lite und CGNAT. Mit Notbremse und Portmapper für TCP und UDP.',
			'Publish services from your home network without port forwarding – via edge servers in Germany, even behind DS-Lite and CGNAT. With emergency brake and port mapper for TCP and UDP.')),
	array('fa-shield-halved', 'text-success', 'DNS64', 'dns64/',
		n64_t('Werbung, Tracker und Malware im ganzen Netz blocken, Gerätegruppen mit eigenen Regeln, eigene DNS-Einträge, Zonen, Weiterleitungen und verschlüsseltes DNS über DoH, DoT und DoQ.',
			'Block ads, trackers and malware across your network, device groups with their own rules, custom DNS records, zones, forwarders and encrypted DNS via DoH, DoT and DoQ.')),
	array('fa-globe', 'text-primary', 'DynDNS64', 'dyndns/',
		n64_t('Deine ipv64.net-Domains automatisch auf IPv4 und IPv6 aktuell halten – mit Verlauf und Meldung bei jedem IP-Wechsel.',
			'Keep your ipv64.net domains up to date on IPv4 and IPv6 automatically – with history and an alert on every IP change.')),
	array('fa-bug', 'text-warning', 'Honeypot64', 'honeypot/',
		n64_t('Fallen für SSH, Web, Mail, Datenbanken und mehr. Wer anklopft, landet über die Meldungen vieler Sensoren auf der v64 Blocklist – und ist für alle gesperrt.',
			'Traps for SSH, web, mail, databases and more. Whoever knocks ends up on the v64 Blocklist through the reports of many sensors – and is blocked for everyone.')),
	array('fa-certificate', 'text-success', n64_t('Zertifikate', 'Certificates'), 'docs/certificates/',
		n64_t('Let\'s Encrypt einmal zentral – per HTTP- oder DNS-Challenge, 26 DNS-Anbieter plus ipv64. Für PROXY64, DoH und DoT von DNS64, Statusseiten und per API für NAS und Proxmox.',
			'Let\'s Encrypt once, centrally – via HTTP or DNS challenge, 26 DNS providers plus ipv64. For PROXY64, DoH and DoT of DNS64, status pages and via API for NAS and Proxmox.')),
	array('fa-circle-nodes', 'text-info', 'Cluster', 'docs/cluster/',
		n64_t('Mehrere Nodes – etwa Raspberry Pi, VPS und bei den Eltern – gleichen sich direkt ab, immer verschlüsselt per HTTPS. Mit oder ohne ipv64-Account.',
			'Several nodes – say a Raspberry Pi, a VPS and one at your parents\' – sync directly with each other, always encrypted via HTTPS. With or without an ipv64 account.')),
	array('fa-server', 'text-secondary', 'Proxmox VE', 'docs/proxmox/',
		n64_t('Nodes, VMs und Container eines Proxmox-Clusters nur lesend überwachen – Abstürze, Neustarts, CPU, RAM und Disk mit Graphen und Regeln.',
			'Monitor the nodes, VMs and containers of a Proxmox cluster read-only – crashes, restarts, CPU, RAM and disk with graphs and rules.')),
	array('fa-robot', 'text-secondary', n64_t('KI-Schnittstelle (MCP)', 'AI interface (MCP)'), 'docs/mcp/',
		n64_t('Claude Code, Cursor oder VS Code fragen über MCP den Zustand der Node ab – nur lesen, nur aus dem Heimnetz, eigene Schlüssel mit Rechten je Bereich.',
			'Claude Code, Cursor or VS Code query the node\'s state via MCP – read-only, home network only, separate keys with permissions per area.')),
	array('fa-box-archive', 'text-secondary', n64_t('Backup & Update', 'Backup & update'), 'docs/update-backup/',
		n64_t('Backups erstellen und einspielen – das Archiv ist mit deinem Passwort verschlüsselt. Dazu Konfiguration exportieren und den Node zurücksetzen.',
			'Create and restore backups – the archive is encrypted with your password. Plus exporting the configuration and resetting the node.')),
	array('fa-bell', 'text-danger', n64_t('Benachrichtigungen', 'Notifications'), 'docs/notifications/',
		n64_t('E-Mail, Telegram, Discord, ntfy, Gotify, Pushover und Webhooks – ein Kanal für alles, mit Flatter-Erkennung, Sammelmeldungen und Ruhezeiten.',
			'E-mail, Telegram, Discord, ntfy, Gotify, Pushover and webhooks – one channel for everything, with flap detection, grouped alerts and quiet times.')),
);
?>
<style>
.n64-dark{display:none!important}
html[data-theme="dark"] .n64-light{display:none!important}
html[data-theme="dark"] .n64-dark{display:inline!important}
.n64-orange{color:#f59c1a}
.n64-card{border-top:3px solid #f59c1a}
</style>
<?php if($userid != ""){ echo "<p></p>"; } ?>

	<div class="jumbotron jumbotron-fluid pt-3 pb-3 mt-0">
		<div class="container">
			<a class="float-right small" href="<?php echo $n64En ? 'node64.php' : 'node64.php?lang=en'; ?>"><?php echo $n64En ? 'Deutsch' : 'English'; ?></a>
			<p class="mb-2"><span class="badge badge-dark"><?php echo n64_t('Offizieller Container von ipv64.net', 'Official container by ipv64.net'); ?></span>
				<span class="badge badge-warning"><?php echo n64_t('Image bald verfügbar', 'Image coming soon'); ?></span></p>
			<h1 class="display-4">
				<img src="/img/node64/node64.svg" height="60" alt="Node64" class="mb-3 n64-light"><img src="/img/node64/node64_dark.svg" height="60" alt="Node64" class="mb-3 n64-dark">
			</h1>
			<h2 class="h3 mb-3"><?php echo n64_t('Dein Homelab. Überwacht, geschützt, erreichbar.', 'Your homelab. Monitored, protected, reachable.'); ?></h2>
			<p class="lead"><?php echo n64_t('Node64 ist die Schaltzentrale für dein Heimnetz: Healthchecks mit Statusseiten, Reverse-Proxy mit Let\'s Encrypt und CDN-Tunnel, DNS-Filter mit DoH/DoT, DynDNS und ein Honeypot, der zusammen mit der Community Angreifer aussperrt – in einem einzigen Docker-Container. Alles läuft lokal bei dir; verbunden mit deinem ipv64-Account kommt die Außensicht dazu.',
				'Node64 is the control center for your home network: health checks with status pages, a reverse proxy with Let\'s Encrypt and CDN tunnel, DNS filtering with DoH/DoT, DynDNS and a honeypot that locks out attackers together with the community – in a single Docker container. Everything runs locally; connected to your ipv64 account, you also get the view from outside.'); ?></p>
			<p class="mb-3">
				<span class="badge badge-light border"><i class="fa-solid fa-cube"></i> <?php echo n64_t('Ein Container, ein Binary', 'One container, one binary'); ?></span>
				<span class="badge badge-light border"><i class="fa-solid fa-microchip"></i> amd64, arm64 &amp; armv7 · Raspberry Pi</span>
				<span class="badge badge-light border"><i class="fa-solid fa-plug-circle-xmark"></i> <?php echo n64_t('Läuft auch komplett offline', 'Works fully offline'); ?></span>
				<span class="badge badge-light border"><i class="fa-solid fa-flag"></i> Made in Germany</span>
				<span class="badge badge-light border"><i class="fa-solid fa-euro-sign"></i> <?php echo n64_t('0 € für Node64 selbst', '€0 for Node64 itself'); ?></span>
			</p>
			<a class="btn btn-primary mb-1" href="<?php echo n64_url(); ?>" target="_blank" rel="noopener"><i class="fa-solid fa-arrow-up-right-from-square"></i> <?php echo n64_t('Zu node64.de', 'Go to node64.de'); ?></a>
			<a class="btn btn-outline-secondary mb-1" href="<?php echo n64_url('docs/installation/'); ?>" target="_blank" rel="noopener"><i class="fa-solid fa-download"></i> <?php echo n64_t('Installationsanleitung', 'Installation guide'); ?></a>
			<a class="btn btn-outline-secondary mb-1" href="#n64-module"><i class="fa-solid fa-table-cells-large"></i> <?php echo n64_t('Module ansehen', 'Explore the modules'); ?></a>
		</div>
	</div>

<div class="container mt-4">
	<div class="row">
		<div class="col-12 col-lg-6 pb-3">
			<div class="list-group">
				<div class="list-group-item flex-column align-items-start list-group-item-success">
					<h5 class="mb-1"><i class="fa-solid fa-house-signal"></i> <?php echo n64_t('Lokal zuerst', 'Local first'); ?></h5>
					<p class="mb-1"><?php echo n64_t('Node64 läuft vollständig in deinem Netz – ohne Account, ohne Cloud, auch wenn das Internet weg ist. Datenbank, Messwerte, Logs und Schlüssel liegen auf deiner Node; Geheimnisse wie Tokens liegen verschlüsselt in der Datenbank.',
						'Node64 runs entirely in your network – without an account, without a cloud, even when the internet is down. Database, measurements, logs and keys live on your node; secrets such as tokens are stored encrypted in the database.'); ?></p>
				</div>
				<div class="list-group-item flex-column align-items-start">
					<h5 class="mb-1"><i class="fa-solid fa-link"></i> <?php echo n64_t('Verbunden mit deinem ipv64-Account', 'Connected to your ipv64 account'); ?></h5>
					<p class="mb-1"><?php echo n64_t('Optional mit deinem ipv64.net-API-Key verknüpfen: ipv64.net prüft deine Dienste zusätzlich aus dem Internet und meldet sich, wenn dein ganzer Anschluss offline ist. Checks, Domains und Meldungen siehst du auch im ipv64.net-Portal.',
						'Optionally link it with your ipv64.net API key: ipv64.net also checks your services from the internet and alerts you when your whole connection is offline. Checks, domains and alerts are also available in the ipv64.net portal.'); ?></p>
				</div>
				<div class="list-group-item flex-column align-items-start">
					<h5 class="mb-1"><i class="fa-solid fa-layer-group"></i> <?php echo n64_t('Ein Container statt vieler', 'One container instead of many'); ?></h5>
					<p class="mb-1"><?php echo n64_t('Statt Uptime Kuma, Nginx Proxy Manager, Cloudflare Tunnel, Pi-hole, einem DynDNS-Skript und einem Honeypot einzeln zu pflegen, schaltest du in Node64 einfach ein, was du brauchst. Eine Oberfläche, ein Login, ein Backup.',
						'Instead of maintaining Uptime Kuma, Nginx Proxy Manager, Cloudflare Tunnel, Pi-hole, a DynDNS script and a honeypot separately, you simply switch on what you need in Node64. One interface, one login, one backup.'); ?></p>
				</div>
				<div class="list-group-item flex-column align-items-start list-group-item-warning">
					<h5 class="mb-1"><i class="fa-solid fa-user-shield"></i> <?php echo n64_t('Sicher ab Werk', 'Secure by default'); ?></h5>
					<p class="mb-1"><?php echo n64_t('Kein Standardpasswort, Zwei-Faktor-Anmeldung, Passkeys, Single Sign-on mit Authelia, Authentik oder Keycloak und ein lückenloses Audit-Log.',
						'No default password, two-factor login, passkeys, single sign-on with Authelia, Authentik or Keycloak and a complete audit log.'); ?></p>
				</div>
				<a href="/account.php" class="list-group-item list-group-item-action list-group-item-success">
					<h5 class="mb-1"><i class="fa-solid fa-id-card"></i> <?php echo n64_t('Kostenlosen ipv64.net-Account anlegen', 'Create a free ipv64.net account'); ?></h5>
					<p class="mb-1"><?php echo n64_t('Node64 läuft auch ohne Account – mit Account kommen Prüfung von außen, CDN64 und die v64 Blocklist dazu.', 'Node64 also runs without an account – with one you add outside checks, CDN64 and the v64 Blocklist.'); ?></p>
				</a>
			</div>
		</div>
		<div class="col-12 col-lg-6 pb-3">
			<div class="card">
				<div class="card-header"><i class="fa-solid fa-gauge-high float-right"></i> <?php echo n64_t('Das Dashboard deiner Node', 'Your node\'s dashboard'); ?></div>
				<div class="card-body">
					<?php echo n64_shot('dashboard', n64_t('Node64 Dashboard mit Healthchecks, DNS64 und PROXY64', 'Node64 dashboard with health checks, DNS64 and PROXY64')); ?>
					<p class="mt-3 mb-0"><?php echo n64_t('Oberfläche, Meldungen und Doku auf Deutsch und Englisch, heller und dunkler Modus, anpassbares Dashboard mit Drag &amp; Drop. Alles, was die Oberfläche kann, geht auch per JSON-API; Metriken für Prometheus und Grafana inklusive.',
						'Interface, alerts and docs in English and German, light and dark mode, a dashboard you can rearrange with drag &amp; drop. Everything the interface can do is also available through a JSON API; metrics for Prometheus and Grafana included.'); ?></p>
				</div>
			</div>
		</div>
	</div>

	<h3 class="mt-3 mb-1" id="n64-module"><i class="fa-solid fa-puzzle-piece n64-orange"></i> <?php echo n64_t('Die Module', 'The modules'); ?></h3>
	<p class="text-muted"><?php echo n64_t('Schalte ein, was du brauchst – die Module kennen sich und greifen ineinander.', 'Switch on what you need – the modules know each other and work together.'); ?></p>
	<div class="row">
		<?php foreach($n64Modules as [$icon, $color, $title, $path, $text]) { ?>
		<div class="col-12 col-md-6 col-lg-4 pb-3">
			<div class="card h-100 n64-card">
				<div class="card-body">
					<h5 class="card-title"><i class="fa-solid <?php echo $icon; ?> <?php echo $color; ?>"></i> <?php echo htmlspecialchars($title, ENT_QUOTES, 'UTF-8'); ?></h5>
					<p class="card-text small"><?php echo $text; ?></p>
				</div>
				<div class="card-footer bg-transparent border-0 pt-0"><a class="small" href="<?php echo n64_url($path); ?>" target="_blank" rel="noopener"><?php echo n64_t('Mehr auf node64.de', 'More on node64.de'); ?> <i class="fa-solid fa-arrow-right"></i></a></div>
			</div>
		</div>
		<?php } ?>
	</div>

	<h3 class="mt-3 mb-3"><i class="fa-solid fa-star n64-orange"></i> Highlights</h3>

	<div class="row align-items-center pb-4">
		<div class="col-12 col-lg-5 pb-3">
			<h4><i class="fa-solid fa-cloud-arrow-up text-info"></i> <?php echo n64_t('Online ohne Portfreigabe', 'Online without port forwarding'); ?></h4>
			<p><?php echo n64_t('CDN64 bringt Dienste über einen ausgehenden, verschlüsselten Tunnel zu den Edge-Servern in Nürnberg und Falkenstein – auch hinter DS-Lite und CGNAT, deine IP bleibt verborgen. Eingeschaltet wird mit einem Klick am Proxy-Host in PROXY64.',
				'CDN64 publishes services through an outbound, encrypted tunnel to the edge servers in Nuremberg and Falkenstein – even behind DS-Lite and CGNAT, and your IP stays hidden. You switch it on with one click at the proxy host in PROXY64.'); ?></p>
			<ul class="small">
				<li><?php echo n64_t('Modus 1 reicht TLS Ende-zu-Ende durch, Modus 2 terminiert auf den Edge-Servern.', 'Mode 1 keeps TLS end-to-end, mode 2 terminates on the edge servers.'); ?></li>
				<li><?php echo n64_t('Portmapper: SSH, WireGuard, Spiele-Server oder die Proxmox-Oberfläche – rohe TCP- und UDP-Ports durch den Tunnel, ohne offenen Port zu Hause.', 'Port mapper: SSH, WireGuard, game servers or the Proxmox interface – raw TCP and UDP ports through the tunnel, without an open port at home.'); ?></li>
				<li><?php echo n64_t('Load-Balancing über beide Server und eine Notbremse, die einen Namen sofort pausiert.', 'Load balancing across both servers and an emergency brake that pauses a name instantly.'); ?></li>
			</ul>
			<a class="btn btn-sm btn-outline-secondary" href="<?php echo n64_url('cdn64-tunnel/'); ?>" target="_blank" rel="noopener">CDN64 <i class="fa-solid fa-arrow-right"></i></a>
		</div>
		<div class="col-12 col-lg-7 pb-3"><?php echo n64_shot('proxy64', n64_t('PROXY64 Proxy-Hosts mit CDN64-Schalter', 'PROXY64 proxy hosts with CDN64 switch')); ?></div>
	</div>

	<div class="row align-items-center pb-4">
		<div class="col-12 col-lg-7 pb-3 order-2 order-lg-1"><?php echo n64_shot('status', n64_t('Öffentliche Statusseite aus Node64-Healthchecks', 'Public status page made from Node64 health checks')); ?></div>
		<div class="col-12 col-lg-5 pb-3 order-1 order-lg-2">
			<h4><i class="fa-solid fa-heart-pulse text-danger"></i> <?php echo n64_t('Healthchecks lokal und online – mit Statusseiten', 'Health checks local and online – with status pages'); ?></h4>
			<p><?php echo n64_t('Checks laufen lokal auf deiner Node und auf Wunsch zusätzlich über die Server von ipv64.net. Aus deinen Checks wird mit wenigen Klicks eine öffentliche Statusseite – auf deiner Node, auf Wunsch unter eigener Domain über PROXY64 und CDN64.',
				'Checks run locally on your node and, if you like, additionally via the ipv64.net servers. A few clicks turn your checks into a public status page – on your node, or on your own domain via PROXY64 and CDN64.'); ?></p>
			<ul class="small">
				<li><?php echo n64_t('Tagesbalken für 30, 60 oder 90 Tage; Störungen und Wartungen erscheinen von selbst.', 'Daily bars for 30, 60 or 90 days; incidents and maintenance show up on their own.'); ?></li>
				<li><?php echo n64_t('Proxmox VE: Nodes, VMs und Container nur lesend überwachen, mit Graphen und Regeln.', 'Proxmox VE: monitor nodes, VMs and containers read-only, with graphs and rules.'); ?></li>
				<li><?php echo n64_t('Besucher sehen nur Namen, Zustand und Verfügbarkeit – keine Ziele, keine IPs.', 'Visitors only see names, state and availability – no targets, no IPs.'); ?></li>
			</ul>
			<a class="btn btn-sm btn-outline-secondary" href="<?php echo n64_url('healthchecks/'); ?>" target="_blank" rel="noopener">Healthchecks <i class="fa-solid fa-arrow-right"></i></a>
		</div>
	</div>

	<div class="row align-items-center pb-4">
		<div class="col-12 col-lg-5 pb-3">
			<h4><i class="fa-solid fa-shield-halved text-success"></i> <?php echo n64_t('DNS im eigenen Netz', 'DNS in your own network'); ?></h4>
			<p><?php echo n64_t('DNS64 blockt Werbung, Tracker und Malware für alle Geräte im Netz. Gerätegruppen bekommen eigene Regeln, eigene Einträge, Zonen, lokale Namen und Weiterleitungen gehören dazu. Verschlüsselt per DoH, DoT oder DoQ – von deinen Geräten zu DNS64 und von DNS64 zu den Upstreams.',
				'DNS64 blocks ads, trackers and malware for every device on your network. Device groups get their own rules; custom records, zones, local names and forwarders are included. Encrypted via DoH, DoT or DoQ – from your devices to DNS64 and from DNS64 to the upstreams.'); ?></p>
			<a class="btn btn-sm btn-outline-secondary" href="<?php echo n64_url('dns64/'); ?>" target="_blank" rel="noopener">DNS64 <i class="fa-solid fa-arrow-right"></i></a>
		</div>
		<div class="col-12 col-lg-7 pb-3"><?php echo n64_shot('dns64', n64_t('DNS64 Übersicht mit Anfragen und Blockierungen', 'DNS64 overview with queries and blocks')); ?></div>
	</div>

	<div class="row align-items-center pb-4">
		<div class="col-12 col-lg-7 pb-3 order-2 order-lg-1"><?php echo n64_shot('honeypot', n64_t('Honeypot64: Herkunft der Angriffe auf der Karte', 'Honeypot64: origin of attacks on the map')); ?></div>
		<div class="col-12 col-lg-5 pb-3 order-1 order-lg-2">
			<h4><i class="fa-solid fa-bug text-warning"></i> <?php echo n64_t('Einer sieht den Angriff. Alle sind geschützt.', 'One sees the attack. Everyone is protected.'); ?></h4>
			<p><?php echo n64_t('Honeypot64 stellt Fallen auf, die Angreifer anlocken. Auf Wunsch meldet deine Node sie an ipv64.net. Erst wenn mehrere unabhängige Accounts dieselbe IP sehen, landet sie auf der v64 Blocklist – und die schützt PROXY64, Firewalls und Router aller Nutzer.',
				'Honeypot64 sets up traps that lure attackers. If you like, your node reports them to ipv64.net. Only when several independent accounts see the same IP does it land on the v64 Blocklist – which protects PROXY64, firewalls and routers of all users.'); ?></p>
			<ul class="small">
				<li><?php echo n64_t('Sofort-Sperre in PROXY64 und Firewall-Helfer für nftables.', 'Instant block in PROXY64 and a firewall helper for nftables.'); ?></li>
				<li><?php echo n64_t('Klein: 30–50 MB RAM, auch auf Raspberry Pi und MikroTik-Routern.', 'Small: 30–50 MB RAM, even on a Raspberry Pi and MikroTik routers.'); ?></li>
			</ul>
			<a class="btn btn-sm btn-outline-secondary" href="<?php echo n64_url('honeypot/'); ?>" target="_blank" rel="noopener">Honeypot64 <i class="fa-solid fa-arrow-right"></i></a>
			<a class="btn btn-sm btn-outline-secondary" href="/honeypot/stats.php<?php echo $n64En ? '?lang=en' : ''; ?>"><?php echo n64_t('Live-Statistik', 'Live statistics'); ?> <i class="fa-solid fa-chart-line"></i></a>
		</div>
	</div>

	<div class="row">
		<div class="col-12 col-lg-6 pb-3">
			<div class="card h-100">
				<div class="card-header"><img src="https://ipv64.net/img/logo_64.png" height="16" alt="IPv64 Logo"> <?php echo n64_t('Mit deinem ipv64.net-Account bekommst du zusätzlich', 'With your ipv64.net account you also get'); ?></div>
				<div class="card-body">
					<ul class="mb-0">
						<li><a href="/dyndns"><?php echo n64_t('DynDNS-Domains', 'DynDNS domains'); ?></a> <?php echo n64_t('und eigene Domains mit vollem DNS-Management', 'and your own domains with full DNS management'); ?></li>
						<li><a href="/healthcheck"><?php echo n64_t('Healthchecks online', 'Online health checks'); ?></a> <?php echo n64_t('mit Prüfung von mehreren Standorten', 'from multiple locations'); ?></li>
						<li><a href="/cdn64">CDN64</a> <?php echo n64_t('mit Edge-Servern in Deutschland', 'with edge servers in Germany'); ?></li>
						<li><?php echo n64_t('Die', 'The'); ?> <a href="/v64_blocklists">v64 Blocklist</a> <?php echo n64_t('aus den Honeypot-Meldungen der Community – live für alle, die mitmachen', 'from the community\'s honeypot reports – live for everyone who contributes'); ?></li>
						<li><?php echo n64_t('Mehr Kontingent mit den', 'More quota with the'); ?> <a href="/pricing"><?php echo n64_t('Account-Klassen', 'account plans'); ?></a> <?php echo n64_t('– oder einfach kostenlos starten', '– or simply start for free'); ?></li>
					</ul>
				</div>
			</div>
		</div>
		<div class="col-12 col-lg-6 pb-3">
			<div class="card h-100">
				<div class="card-header"><i class="fa-solid fa-rocket float-right"></i> <?php echo n64_t('In drei Schritten startklar', 'Up and running in three steps'); ?></div>
				<div class="card-body">
					<ol class="mb-2">
						<li><b><?php echo n64_t('Container starten', 'Start the container'); ?></b> – <?php echo n64_t('mit Docker oder Docker Compose, auf Linux, NAS, Proxmox oder Raspberry Pi.', 'with Docker or Docker Compose, on Linux, NAS, Proxmox or Raspberry Pi.'); ?></li>
						<li><b><?php echo n64_t('Assistent durchlaufen', 'Run the setup wizard'); ?></b> – <?php echo n64_t('Sprache wählen, Admin-Konto anlegen. Es gibt kein Standardpasswort.', 'choose your language, create the admin account. There is no default password.'); ?></li>
						<li><b><?php echo n64_t('Module einschalten', 'Switch on modules'); ?></b> – <?php echo n64_t('optional mit deinem ipv64.net-API-Key verknüpfen.', 'optionally link them with your ipv64.net API key.'); ?></li>
					</ol>
					<p class="small text-muted mb-0"><i class="fa-solid fa-circle-info"></i> <?php echo n64_t('Das öffentliche Image erscheint in Kürze. Alles zur Installation steht auf', 'The public image is coming soon. Everything about installing is on'); ?> <a href="<?php echo n64_url('docs/installation/'); ?>" target="_blank" rel="noopener">node64.de</a>.</p>
				</div>
			</div>
		</div>
	</div>
</div>

<div class="bd-masthead mb-3 mt-3" id="content">
	<div class="container-xxl bd-gutter">
		<div class="col-md-8 mx-auto text-center">
			<img src="/img/node64/node64_icon.png" height="120" alt="Node64 Icon" class="d-block mx-auto mb-3" style="border-radius:20px">
			<h2 class="mb-3 fw-semibold lh-1"><?php echo n64_t('Bereit für dein neues Homelab-Cockpit?', 'Ready for your new homelab cockpit?'); ?></h2>
			<p class="lead mb-4"><?php echo n64_t('Die Doku führt dich Schritt für Schritt – vom ersten Check bis zum CDN-Tunnel.', 'The docs guide you step by step – from the first check to the CDN tunnel.'); ?></p>
			<a class="btn btn-lg btn-primary mb-1" href="<?php echo n64_url(); ?>" target="_blank" rel="noopener"><i class="fa-solid fa-arrow-up-right-from-square"></i> node64.de</a>
			<a class="btn btn-lg btn-outline-secondary mb-1" href="<?php echo n64_url('docs/installation/'); ?>" target="_blank" rel="noopener"><i class="fa-solid fa-download"></i> <?php echo n64_t('Installationsanleitung', 'Installation guide'); ?></a>
			<a class="btn btn-lg btn-outline-secondary mb-1" href="<?php echo n64_url('docs/'); ?>" target="_blank" rel="noopener"><i class="fa-solid fa-book"></i> <?php echo n64_t('Dokumentation', 'Documentation'); ?></a>
			<p class="small text-muted mt-3"><?php echo n64_t('Fragen zu Node64? Frag im offiziellen Forum', 'Questions about Node64? Ask in the official forum'); ?> <a href="https://v64.tech/" target="_blank" rel="noopener">v64.tech</a>.</p>
		</div>
	</div>
</div>
<p></p>
<?php
include("footer.php");
?>
