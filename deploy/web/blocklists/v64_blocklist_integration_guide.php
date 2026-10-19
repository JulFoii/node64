<?php
include("header.php");

// Integrationsleitfaden fuer die IPv64-Blocklisten (Englisch, Deutsch mit ?lang=de).
// Die Linux-Skripte liegen unter /blocklists/tools/ und werden hier direkt angezeigt (eine Quelle).
$blgDe = (($_GET['lang'] ?? '') === 'de');
function blg(string $en, string $de): string { global $blgDe; return $blgDe ? $de : $en; }
function blg_code(string $code): string { return '<pre class="bg-light border rounded p-2 small mb-2" style="white-space:pre-wrap"><code>' . htmlspecialchars($code, ENT_QUOTES) . '</code></pre>'; }
function blg_tool(string $file): string { $p = __DIR__ . '/blocklists/tools/' . basename($file); return is_file($p) ? blg_code((string)file_get_contents($p)) : ''; }
$blgBase = 'https://ipv64.net/blocklists/';
?>
<div class="jumbotron jumbotron-fluid p-3 mb-3">
	<div class="container">
		<h1 class="display-4"><img src="https://ipv64.net/img/logo_64.png" height="70" alt="IPv64 Logo" class="mb-2"> <?php echo blg('Blocklists – Integration Guide', 'Blocklisten – Integrationsleitfaden'); ?> <i class="fa-solid fa-shield-halved text-success"></i></h1>
		<p class="lead mb-1"><?php echo blg('Step-by-step instructions for firewalls, servers and reverse proxies. The Linux scripts and the nginx and CrowdSec examples were tested with the live lists.',
			'Schritt-für-Schritt-Anleitungen für Firewalls, Server und Reverse-Proxys. Die Linux-Skripte sowie die Beispiele für nginx und CrowdSec sind mit den echten Listen getestet.'); ?></p>
		<p class="mb-0"><a href="?lang=en"<?php echo $blgDe ? '' : ' class="font-weight-bold"'; ?>>English</a> · <a href="?lang=de"<?php echo $blgDe ? ' class="font-weight-bold"' : ''; ?>>Deutsch</a> · <a href="/v64_blocklists"><?php echo blg('All lists and download links', 'Alle Listen und Download-Links'); ?></a></p>
	</div>
</div>
<div class="container mb-4">
	<div class="alert alert-warning">
		<strong><?php echo blg('Before you start', 'Bevor du loslegst'); ?>:</strong>
		<?php echo blg('A blocklist drops all traffic from the listed networks. Try it on a test system first, keep a way to access your device (console, VPN) and start with a list with few false positives (Spamhaus DROP or FireHOL Level 1).',
			'Eine Blockliste verwirft allen Verkehr aus den gelisteten Netzen. Probiere sie zuerst auf einem Testsystem, behalte einen Zugang zum Gerät (Konsole, VPN) und beginne mit einer Liste mit wenigen Fehlalarmen (Spamhaus DROP oder FireHOL Level 1).'); ?>
	</div>

	<div class="card mb-3" id="choose">
		<div class="card-header"><i class="fa-solid fa-list-check"></i> 1. <?php echo blg('Choose a list', 'Liste wählen'); ?></div>
		<div class="card-body">
			<div class="table-responsive"><table class="table table-sm">
				<thead><tr><th><?php echo blg('List (ID)', 'Liste (ID)'); ?></th><th><?php echo blg('Content', 'Inhalt'); ?></th><th><?php echo blg('False positives', 'Fehlalarme'); ?></th><th><?php echo blg('Recommended for', 'Empfohlen für'); ?></th></tr></thead>
				<tbody>
					<tr><td><code>spamhaus_drop</code></td><td><?php echo blg('Hijacked and criminal networks (Spamhaus DROP)', 'Gekaperte und kriminelle Netze (Spamhaus DROP)'); ?></td><td><span class="badge badge-success"><?php echo blg('very low', 'sehr gering'); ?></span></td><td><?php echo blg('everyone, inbound and outbound', 'alle, eingehend und ausgehend'); ?></td></tr>
					<tr><td><code>firehole_l1</code></td><td><?php echo blg('FireHOL Level 1: DROP, Feodo, bogons and more', 'FireHOL Level 1: DROP, Feodo, reservierte Netze u. a.'); ?></td><td><span class="badge badge-success"><?php echo blg('low', 'gering'); ?></span></td><td><?php echo blg('routers and servers (good default)', 'Router und Server (guter Standard)'); ?></td></tr>
					<tr><td><code>blocklistde_all</code></td><td><?php echo blg('Attackers reported to blocklist.de in the last 48 hours (SSH, mail, web)', 'Angreifer, die blocklist.de in den letzten 48 Stunden gemeldet wurden (SSH, Mail, Web)'); ?></td><td><span class="badge badge-warning"><?php echo blg('medium', 'mittel'); ?></span></td><td><?php echo blg('servers reachable from the Internet', 'Server, die aus dem Internet erreichbar sind'); ?></td></tr>
					<tr><td><code>dshield1</code></td><td><?php echo blg('DShield: top 20 attacking /24 networks', 'DShield: die 20 aktivsten angreifenden /24-Netze'); ?></td><td><span class="badge badge-success"><?php echo blg('low', 'gering'); ?></span></td><td><?php echo blg('in addition to one of the lists above', 'zusätzlich zu einer Liste oben'); ?></td></tr>
					<tr><td><code>tor_exit</code>, <code>tor_all</code></td><td><?php echo blg('Tor exit nodes / all Tor relays', 'Tor-Exit-Knoten / alle Tor-Relays'); ?></td><td><span class="badge badge-secondary"><?php echo blg('by design', 'gewollt'); ?></span></td><td><?php echo blg('only if you want to lock out Tor users', 'nur, wenn du Tor-Nutzer aussperren willst'); ?></td></tr>
					<tr><td><code>all</code></td><td><?php echo blg('All lists above combined', 'Alle Listen oben zusammen'); ?></td><td><span class="badge badge-warning"><?php echo blg('medium', 'mittel'); ?></span></td><td><?php echo blg('<strong>contains the Tor lists</strong> – Tor users are blocked too', '<strong>enthält die Tor-Listen</strong> – Tor-Nutzer werden mit gesperrt'); ?></td></tr>
				</tbody>
			</table></div>
			<p class="mb-1"><?php echo blg('Every list is available in three variants; replace <code>&lt;id&gt;</code> with the ID from the table:', 'Jede Liste gibt es in drei Varianten; <code>&lt;id&gt;</code> durch die ID aus der Tabelle ersetzen:'); ?></p>
			<ul class="mb-2">
				<li><?php echo blg('IPv4 and IPv6', 'IPv4 und IPv6'); ?>: <code><?php echo $blgBase; ?>ipv64_blocklist_&lt;id&gt;.txt</code></li>
				<li><?php echo blg('IPv4 only', 'nur IPv4'); ?>: <code><?php echo $blgBase; ?>ipv64_blocklist_v4_&lt;id&gt;.txt</code></li>
				<li><?php echo blg('IPv6 only', 'nur IPv6'); ?>: <code><?php echo $blgBase; ?>ipv64_blocklist_v6_&lt;id&gt;.txt</code></li>
				<li>MikroTik RouterOS: <code><?php echo $blgBase; ?>v64_mikrotik_v4_&lt;id&gt;.rsc</code> <?php echo blg('and', 'und'); ?> <code>…_v6_&lt;id&gt;.rsc</code></li>
			</ul>
			<p class="mb-0 small text-muted"><?php echo blg('Format: one address or network (CIDR) per line, no comments. The lists are regenerated several times a day. Please fetch them at most every 30 minutes; every 1 to 6 hours is enough. Country and continent lists are on the <a href="/v64_blocklists">list page</a>.',
				'Format: eine Adresse oder ein Netz (CIDR) je Zeile, ohne Kommentare. Die Listen werden mehrmals täglich neu erzeugt. Bitte höchstens alle 30 Minuten abrufen; alle 1 bis 6 Stunden reicht. Länder- und Kontinentlisten stehen auf der <a href="/v64_blocklists">Listenseite</a>.'); ?></p>
		</div>
	</div>

	<div class="card mb-3" id="nftables">
		<div class="card-header"><i class="fa-brands fa-linux"></i> 2. Linux: nftables <span class="badge badge-success"><?php echo blg('recommended, tested', 'empfohlen, getestet'); ?></span></div>
		<div class="card-body">
			<p><?php echo blg('For current Debian, Ubuntu, Fedora, Proxmox and most routers on Linux. The script loads IPv4 and IPv6 into a separate table <code>inet ipv64</code> and replaces it atomically. It does not touch your other rules. If a download fails, the old list stays active. Traffic forwarded to Docker containers or NATed hosts is filtered too.',
				'Für aktuelle Debian-, Ubuntu-, Fedora- und Proxmox-Systeme und die meisten Linux-Router. Das Skript lädt IPv4 und IPv6 in eine eigene Tabelle <code>inet ipv64</code> und tauscht sie in einem Schritt aus. Deine übrigen Regeln bleiben unberührt. Schlägt ein Download fehl, bleibt die alte Liste aktiv. Auch Verkehr, der an Docker-Container oder per NAT weitergeleitet wird, wird gefiltert.'); ?></p>
			<p class="mb-1"><strong><?php echo blg('Install (as root)', 'Einrichten (als root)'); ?>:</strong></p>
			<?php echo blg_code("apt install -y nftables curl\ncurl -fsSo /usr/local/sbin/ipv64-blocklist-nft.sh https://ipv64.net/blocklists/tools/ipv64-blocklist-nft.sh\nchmod +x /usr/local/sbin/ipv64-blocklist-nft.sh\n/usr/local/sbin/ipv64-blocklist-nft.sh firehole_l1"); ?>
			<p class="mb-1"><strong><?php echo blg('Update every 4 hours and after a reboot (cron)', 'Alle 4 Stunden und nach einem Neustart aktualisieren (cron)'); ?>:</strong></p>
			<?php echo blg_code("cat > /etc/cron.d/ipv64-blocklist <<'EOF'\n17 */4 * * * root /usr/local/sbin/ipv64-blocklist-nft.sh firehole_l1 >/dev/null\n@reboot      root sleep 30 && /usr/local/sbin/ipv64-blocklist-nft.sh firehole_l1 >/dev/null\nEOF"); ?>
			<p class="mb-1"><strong><?php echo blg('Check and remove', 'Prüfen und entfernen'); ?>:</strong></p>
			<?php echo blg_code("nft list chain inet ipv64 input     # counters show dropped packets\nnft delete table inet ipv64          # remove the blocklist completely"); ?>
			<details><summary class="small"><?php echo blg('Show the script', 'Skript anzeigen'); ?></summary><?php echo blg_tool('ipv64-blocklist-nft.sh'); ?></details>
		</div>
	</div>

	<div class="card mb-3" id="ipset">
		<div class="card-header"><i class="fa-brands fa-linux"></i> 3. Linux: iptables + ipset <span class="badge badge-success"><?php echo blg('tested', 'getestet'); ?></span></div>
		<div class="card-body">
			<p><?php echo blg('For systems that still use iptables. The script fills one set each for IPv4 and IPv6 via <code>ipset restore</code>, swaps it in and adds the DROP rules only once (INPUT, FORWARD and, if present, Docker\'s DOCKER-USER chain).',
				'Für Systeme, die noch iptables nutzen. Das Skript füllt je ein Set für IPv4 und IPv6 per <code>ipset restore</code>, tauscht es ein und legt die DROP-Regeln nur einmal an (INPUT, FORWARD und, falls vorhanden, Dockers Kette DOCKER-USER).'); ?></p>
			<?php echo blg_code("apt install -y ipset iptables curl\ncurl -fsSo /usr/local/sbin/ipv64-blocklist-ipset.sh https://ipv64.net/blocklists/tools/ipv64-blocklist-ipset.sh\nchmod +x /usr/local/sbin/ipv64-blocklist-ipset.sh\n/usr/local/sbin/ipv64-blocklist-ipset.sh firehole_l1\necho '17 */4 * * * root /usr/local/sbin/ipv64-blocklist-ipset.sh firehole_l1 >/dev/null' > /etc/cron.d/ipv64-blocklist\necho '@reboot root sleep 30 && /usr/local/sbin/ipv64-blocklist-ipset.sh firehole_l1 >/dev/null' >> /etc/cron.d/ipv64-blocklist"); ?>
			<p class="small text-muted"><?php echo blg('The @reboot line restores sets and rules after a restart, so ipset-persistent is not needed. Docker restarts its chains when the daemon restarts; run the script again afterwards.',
				'Die @reboot-Zeile stellt Sets und Regeln nach einem Neustart wieder her, ipset-persistent ist dafür nicht nötig. Docker legt seine Ketten beim Neustart des Dienstes neu an; danach das Skript einmal erneut ausführen.'); ?></p>
			<details><summary class="small"><?php echo blg('Show the script', 'Skript anzeigen'); ?></summary><?php echo blg_tool('ipv64-blocklist-ipset.sh'); ?></details>
		</div>
	</div>

	<div class="card mb-3" id="pfsense">
		<div class="card-header"><i class="fa-solid fa-shield"></i> 4. pfSense</div>
		<div class="card-body">
			<ol class="mb-2">
				<li><?php echo blg('<strong>Firewall › Aliases › URLs › Add</strong>: Type <em>URL Table (IPs)</em>, name e.g. <code>IPv64_firehol</code>, URL <code>https://ipv64.net/blocklists/ipv64_blocklist_firehole_l1.txt</code>, update frequency <code>1</code> day. Save and <em>Apply Changes</em>.',
					'<strong>Firewall › Aliases › URLs › Add</strong>: Typ <em>URL Table (IPs)</em>, Name z. B. <code>IPv64_firehol</code>, URL <code>https://ipv64.net/blocklists/ipv64_blocklist_firehole_l1.txt</code>, Aktualisierung <code>1</code> Tag. Speichern und <em>Apply Changes</em>.'); ?></li>
				<li><?php echo blg('<strong>Firewall › Rules › WAN › Add (arrow up = top)</strong>: Action <em>Block</em>, Address Family <em>IPv4+IPv6</em>, Protocol <em>Any</em>, <strong>Source</strong>: <em>Single host or alias</em> = <code>IPv64_firehol</code>, Destination <em>any</em>. Save and apply.',
					'<strong>Firewall › Rules › WAN › Add (Pfeil nach oben = ganz oben)</strong>: Action <em>Block</em>, Address Family <em>IPv4+IPv6</em>, Protocol <em>Any</em>, <strong>Source</strong>: <em>Single host or alias</em> = <code>IPv64_firehol</code>, Destination <em>any</em>. Speichern und übernehmen.'); ?></li>
				<li><?php echo blg('Optional, recommended for Spamhaus DROP: <strong>Firewall › Rules › LAN</strong>, Block rule at the top with <strong>Destination</strong> = the alias. This stops infected devices from contacting the listed networks.',
					'Optional, für Spamhaus DROP empfohlen: <strong>Firewall › Rules › LAN</strong>, Block-Regel ganz oben mit <strong>Destination</strong> = Alias. So erreichen infizierte Geräte die gelisteten Netze nicht.'); ?></li>
			</ol>
			<p class="small text-muted mb-0"><?php echo blg('Large lists (countries) may exceed <em>Firewall Maximum Table Entries</em> under System › Advanced › Firewall &amp; NAT; raise the value if the alias stays empty. Diagnostics › Tables shows the loaded entries.',
				'Große Listen (Länder) können <em>Firewall Maximum Table Entries</em> unter System › Advanced › Firewall &amp; NAT überschreiten; den Wert erhöhen, wenn der Alias leer bleibt. Unter Diagnostics › Tables siehst du die geladenen Einträge.'); ?></p>
		</div>
	</div>

	<div class="card mb-3" id="opnsense">
		<div class="card-header"><i class="fa-solid fa-shield"></i> 5. OPNsense</div>
		<div class="card-body">
			<ol class="mb-2">
				<li><?php echo blg('<strong>Firewall › Aliases › +</strong>: Type <em>URL Table (IPs)</em>, name e.g. <code>IPv64_firehol</code>, refresh frequency <code>0</code> days <code>4</code> hours, content <code>https://ipv64.net/blocklists/ipv64_blocklist_firehole_l1.txt</code>. Save and <em>Apply</em>.',
					'<strong>Firewall › Aliases › +</strong>: Typ <em>URL Table (IPs)</em>, Name z. B. <code>IPv64_firehol</code>, Aktualisierung <code>0</code> Tage <code>4</code> Stunden, Inhalt <code>https://ipv64.net/blocklists/ipv64_blocklist_firehole_l1.txt</code>. Speichern und <em>Apply</em>.'); ?></li>
				<li><?php echo blg('<strong>Firewall › Rules › WAN › +</strong>: Action <em>Block</em>, Direction <em>in</em>, TCP/IP Version <em>IPv4+IPv6</em>, Protocol <em>any</em>, <strong>Source</strong> = <code>IPv64_firehol</code>, Destination <em>any</em>. Save, drag the rule to the top and apply.',
					'<strong>Firewall › Rules › WAN › +</strong>: Action <em>Block</em>, Direction <em>in</em>, TCP/IP Version <em>IPv4+IPv6</em>, Protocol <em>any</em>, <strong>Source</strong> = <code>IPv64_firehol</code>, Destination <em>any</em>. Speichern, Regel ganz nach oben ziehen und übernehmen.'); ?></li>
				<li><?php echo blg('Optional on LAN: Block rule with <strong>Destination</strong> = alias (outbound).', 'Optional auf LAN: Block-Regel mit <strong>Destination</strong> = Alias (ausgehend).'); ?></li>
			</ol>
			<p class="small text-muted mb-0"><?php echo blg('Firewall › Diagnostics › Aliases shows the loaded entries and the last update.', 'Unter Firewall › Diagnostics › Aliases siehst du die geladenen Einträge und die letzte Aktualisierung.'); ?></p>
		</div>
	</div>

	<div class="card mb-3" id="mikrotik">
		<div class="card-header"><i class="fa-solid fa-network-wired"></i> 6. MikroTik RouterOS 7</div>
		<div class="card-body">
			<p><?php echo blg('ipv64.net provides ready-made import files. Each file first removes its own old entries and then adds the current ones to the address list <code>IPv64-&lt;id&gt;</code>. The following script downloads the file, imports it and is run by the scheduler every 6 hours. Paste it into the terminal (Winbox › New Terminal):',
				'ipv64.net stellt fertige Importdateien bereit. Jede Datei entfernt zuerst ihre eigenen alten Einträge und trägt dann die aktuellen in die Adressliste <code>IPv64-&lt;id&gt;</code> ein. Das folgende Skript lädt die Datei, importiert sie und läuft per Scheduler alle 6 Stunden. Im Terminal einfügen (Winbox › New Terminal):'); ?></p>
			<?php echo blg_code("/system script add name=ipv64-blocklist policy=read,write,test source={\n  :foreach v in={\"v4\";\"v6\"} do={\n    :local f (\"ipv64-\" . \$v . \".rsc\")\n    /tool fetch url=(\"https://ipv64.net/blocklists/v64_mikrotik_\" . \$v . \"_firehole_l1.rsc\") dst-path=\$f\n    :delay 2s\n    /import file-name=\$f\n    /file remove \$f\n  }\n}\n/system scheduler add name=ipv64-blocklist interval=6h start-time=startup on-event=\"/system script run ipv64-blocklist\"\n/system script run ipv64-blocklist\n/ip firewall raw add chain=prerouting src-address-list=IPv64-firehole_l1 action=drop comment=\"IPv64 blocklist\"\n/ipv6 firewall raw add chain=prerouting src-address-list=IPv64-firehole_l1 action=drop comment=\"IPv64 blocklist\""); ?>
			<p class="small text-muted mb-0"><?php echo blg('The raw rules drop the traffic before connection tracking, for the router and the LAN. Move them to the top of the raw table if you have other raw rules. The import of large lists takes a few seconds. /ip firewall address-list print count-only where list=IPv64-firehole_l1 shows the number of entries.',
				'Die raw-Regeln verwerfen den Verkehr vor dem Connection-Tracking, für Router und LAN. Hast du weitere raw-Regeln, diese nach oben schieben. Der Import großer Listen dauert einige Sekunden. /ip firewall address-list print count-only where list=IPv64-firehole_l1 zeigt die Anzahl der Einträge.'); ?></p>
		</div>
	</div>

	<div class="card mb-3" id="nginx">
		<div class="card-header"><i class="fa-solid fa-server"></i> 7. nginx <span class="badge badge-success"><?php echo blg('tested', 'getestet'); ?></span></div>
		<div class="card-body">
			<p><?php echo blg('For a web server or reverse proxy without firewall access. The <code>geo</code> module checks networks efficiently, even with tens of thousands of entries. Blocked clients get HTTP 403.',
				'Für einen Webserver oder Reverse-Proxy ohne Zugriff auf die Firewall. Das Modul <code>geo</code> prüft Netze effizient, auch bei Zehntausenden Einträgen. Gesperrte Clients bekommen HTTP 403.'); ?></p>
			<p class="mb-1"><strong><?php echo blg('1. Fetch the list as a geo file (cron, e.g. every 4 hours)', '1. Liste als geo-Datei holen (cron, z. B. alle 4 Stunden)'); ?>:</strong></p>
			<?php echo blg_code("curl -fsS https://ipv64.net/blocklists/ipv64_blocklist_blocklistde_all.txt \\\n  | awk '/^[0-9A-Fa-f:.]+(\\/[0-9]+)?\$/ {print \$1\" 1;\"}' > /etc/nginx/ipv64-geo.conf.new \\\n  && [ -s /etc/nginx/ipv64-geo.conf.new ] && mv /etc/nginx/ipv64-geo.conf.new /etc/nginx/ipv64-geo.conf \\\n  && nginx -t -q && systemctl reload nginx"); ?>
			<p class="mb-1"><strong><?php echo blg('2. Use it in nginx.conf', '2. In der nginx.conf verwenden'); ?>:</strong></p>
			<?php echo blg_code("http {\n    geo \$ipv64_blocked { default 0; include /etc/nginx/ipv64-geo.conf; }\n    server {\n        # ...\n        if (\$ipv64_blocked) { return 403; }\n    }\n}"); ?>
			<p class="small text-muted mb-0"><?php echo blg('Behind Cloudflare or another proxy, configure <code>real_ip_header</code> first, otherwise nginx sees the proxy address.', 'Hinter Cloudflare oder einem anderen Proxy zuerst <code>real_ip_header</code> einrichten, sonst sieht nginx die Adresse des Proxys.'); ?></p>
		</div>
	</div>

	<div class="card mb-3" id="crowdsec">
		<div class="card-header"><i class="fa-solid fa-users-viewfinder"></i> 8. CrowdSec <span class="badge badge-success"><?php echo blg('tested with 1.6', 'getestet mit 1.6'); ?></span></div>
		<div class="card-body">
			<p><?php echo blg('Import the list as decisions; all your bouncers (firewall, nginx, Traefik …) apply it. The decisions expire after 6 hours, so import again every 4 hours via cron:',
				'Die Liste als Entscheidungen importieren; alle Bouncer (Firewall, nginx, Traefik …) setzen sie um. Die Entscheidungen laufen nach 6 Stunden ab, deshalb alle 4 Stunden per cron neu importieren:'); ?></p>
			<?php echo blg_code("curl -fsSo /tmp/ipv64.txt https://ipv64.net/blocklists/ipv64_blocklist_firehole_l1.txt \\\n  && cscli decisions import -i /tmp/ipv64.txt --format values --duration 6h --reason ipv64-blocklist"); ?>
		</div>
	</div>

	<div class="card mb-3" id="node64">
		<div class="card-header"><i class="fa-solid fa-cube"></i> 9. Node64</div>
		<div class="card-body">
			<p class="mb-0"><?php echo blg('The Node64 container uses the IPv64 blocklists in its reverse proxy CDN64 with one click: <em>CDN64 › Access › Blocklists</em>. It refreshes them every 30 minutes and lets you define exceptions.',
				'Der Node64-Container nutzt die IPv64-Blocklisten in seinem Reverse-Proxy CDN64 mit einem Klick: <em>CDN64 › Zugriff › Blocklisten</em>. Er aktualisiert sie alle 30 Minuten, Ausnahmen kannst du selbst festlegen.'); ?></p>
		</div>
	</div>

	<div class="card mb-3" id="sources">
		<div class="card-header"><i class="fa-solid fa-scale-balanced"></i> 10. <?php echo blg('Sources, false positives and terms', 'Quellen, Fehlalarme und Bedingungen'); ?></div>
		<div class="card-body">
			<p><?php echo blg('ipv64.net combines and cleans public lists: it converts everything to networks, removes duplicates, contained networks and reserved ranges. The entries themselves come from these projects:',
				'ipv64.net fasst öffentliche Listen zusammen und bereinigt sie: alles wird in Netze umgewandelt, Doppelte, enthaltene Netze und reservierte Bereiche fallen weg. Die Einträge selbst stammen aus diesen Projekten:'); ?></p>
			<ul>
				<li><a href="https://www.spamhaus.org/blocklists/do-not-route-or-peer/" target="_blank" rel="noopener">Spamhaus DROP</a></li>
				<li><a href="https://iplists.firehol.org/?ipset=firehol_level1" target="_blank" rel="noopener">FireHOL Level 1</a></li>
				<li><a href="https://www.blocklist.de/en/index.html" target="_blank" rel="noopener">blocklist.de</a></li>
				<li><a href="https://www.dshield.org/" target="_blank" rel="noopener">DShield (SANS ISC)</a></li>
				<li><a href="https://metrics.torproject.org/collector.html" target="_blank" rel="noopener">Tor Project</a></li>
			</ul>
			<p class="mb-0"><?php echo blg('If one of your addresses is listed by mistake, ask the source project to remove it; the change reaches the IPv64 lists with the next update. The lists are free to use; please respect the terms of the source projects and do not use them as the only protection.',
				'Ist eine deiner Adressen fälschlich gelistet, beantrage die Löschung beim jeweiligen Projekt; mit der nächsten Aktualisierung verschwindet sie auch aus den IPv64-Listen. Die Listen sind kostenlos nutzbar; bitte beachte die Bedingungen der Quellprojekte und verlass dich nicht allein auf sie.'); ?></p>
		</div>
	</div>
</div>
<?php
include("footer.php");
?>
