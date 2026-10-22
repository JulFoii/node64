# Node64-Hinweise auf den alten ipv64.net-Seiten (von Hand einfügen)

Diese Seiten liegen nur in `ipv64net_webseite/` (lokale Kopie, evtl. älter als der Server) und werden **nicht**
überschrieben. Bitte jeweils auf dem **Server-Stand** die eine Zeile einfügen. Voraussetzung: `node64_hint.php`,
`node64.php` und `img/node64/` liegen im Web-Root.

Der Baustein `node64_hint.php` kennt drei optionale Variablen (vor dem `include` setzen, danach werden sie geleert):

| Variable | Standard | Zweck |
|---|---|---|
| `$node64_hint` | deutscher Standardsatz | der eine Satz (wird escaped, kein HTML) |
| `$node64_hint_btn` | `Mehr zu Node64` | Text des Knopfs |
| `$node64_hint_href` | `/node64.php` | Ziel des Knopfs (`/node64.php?lang=en` für englische Seiten) |

Wichtig: immer auf **`/node64.php`** verlinken, nicht `/node64` – `/node64/` ist auf dem Server ein Ordner
(`latest.json` für das Update), die `.htaccess`-Regel ohne `.php` greift dort nicht (`!-d`).

Die alten Produktseiten sind englisch, deshalb sind die Sätze unten englisch. Für eine deutsche Variante einfach
`$node64_hint_btn` und `$node64_hint_href` weglassen und den Satz auf Deutsch schreiben.

Alle Anker sind in der lokalen Kopie genau **einmal** vorhanden (geprüft). Eingefügt wird jeweils im
**Landing-Teil (nicht eingeloggt)**, als erste Zeile im Container direkt unter dem Jumbotron.

---

## healthcheck.php

Anker (Zeile ~1471, direkt unter dem Jumbotron „Healthchecks & Monitoring by, IPv64.net“):

```html
		<div class="container pt-4">
```

**Danach** einfügen:

```php
		<?php $node64_hint = "Run health checks locally in your home network too – with status pages and Proxmox VE monitoring: Node64."; $node64_hint_btn = "More about Node64"; $node64_hint_href = "/node64.php?lang=en"; include("node64_hint.php"); ?>
```

## dyndns.php

Anker (Zeile ~1836, letzte Zeile des Jumbotron-Texts):

```html
Free of charge and compatible with the DynDNS2 protocol used by almost every router.</p>
```

Drei Zeilen tiefer folgt `<div class="container">` – **nach diesem** `<div class="container">` einfügen:

```php
		<?php $node64_hint = "Keep your ipv64.net domains up to date automatically on IPv4 and IPv6 – DynDNS64 in Node64, with history and an alert on every IP change."; $node64_hint_btn = "More about Node64"; $node64_hint_href = "/node64.php?lang=en"; include("node64_hint.php"); ?>
```

## dns-server.php (DNS64-Serverliste)

Anker (Zeile ~16, einziges Vorkommen):

```html
		<div class="container mt-2">
```

**Danach** einfügen:

```php
		<?php $node64_hint = "DNS64 also runs in your own network: block ads and trackers, own records and zones, DoH, DoT and DoQ – with Node64."; $node64_hint_btn = "More about Node64"; $node64_hint_href = "/node64.php?lang=en"; include("node64_hint.php"); ?>
```

## dns-setup.php (DNS64-Anleitung)

Anker (Zeile ~17, einziges Vorkommen):

```html
		<div class="container mt-2">
```

**Danach** einfügen:

```php
		<?php $node64_hint = "Prefer a DNS filter inside your home network? DNS64 is a module of Node64 – with device groups, own records and encrypted DNS."; $node64_hint_btn = "More about Node64"; $node64_hint_href = "/node64.php?lang=en"; include("node64_hint.php"); ?>
```

## reverse_proxy.php

Anker (Zeile ~17, einziges Vorkommen):

```html
		<div class="container mt-4">
```

**Danach** einfügen:

```php
		<?php $node64_hint = "Reverse proxy at home: PROXY64 in Node64 with Let's Encrypt, access lists and the ipv64 blocklists – and CDN64 without port forwarding."; $node64_hint_btn = "More about Node64"; $node64_hint_href = "/node64.php?lang=en"; include("node64_hint.php"); ?>
```

## portmapper.php

Anker (Zeile ~17, einziges Vorkommen):

```html
		<div class="container mt-4">
```

**Danach** einfügen:

```php
		<?php $node64_hint = "SSH, WireGuard or game servers without an open port at home: the CDN64 port mapper runs through the Node64 tunnel."; $node64_hint_btn = "More about Node64"; $node64_hint_href = "/node64.php?lang=en"; include("node64_hint.php"); ?>
```

## cdn.php (alte CDN-Seite)

Anker (Zeile ~1419, einziges Vorkommen):

```html
		<div class="container mt-4">
```

**Danach** einfügen:

```php
		<?php $node64_hint = "New: CDN64 – publish services without port forwarding, even behind DS-Lite and CGNAT. Node64 opens the tunnel from your home network."; $node64_hint_btn = "More about Node64"; $node64_hint_href = "/node64.php?lang=en"; include("node64_hint.php"); ?>
```

## blocklistv64.php

Anker (Zeile ~349, letzte Zeile des Jumbotron-Texts):

```html
			  Best suited for <strong>pfSense, OPNsense, Mikrotik and Linux based systems</strong>.</p>
```

Drei Zeilen tiefer folgt `<div class="container">` – **nach diesem** `<div class="container">` einfügen:

```php
		<?php $node64_hint = "The v64 Blocklist grows from Honeypot64 reports – run your own sensor with Node64, the homelab container by ipv64.net."; $node64_hint_btn = "More about Node64"; $node64_hint_href = "/node64.php?lang=en"; include("node64_hint.php"); ?>
```

(`v64_blocklists.php` ist bereits im aktuellen Stand `deploy/web/blocklists/site/v64_blocklists.php` eingebaut.)

## statuspage.php

Anker (Zeile ~270, einziges Vorkommen):

```html
			  <h1 class="display-3">IPv64.net - Monitoring Status Pages</h1>
```

Drei Zeilen tiefer folgt `<div class="container">` – **nach diesem** `<div class="container">` einfügen:

```php
		<?php $node64_hint = "Status pages from your local health checks – on your node or on your own domain via PROXY64 and CDN64: Node64."; $node64_hint_btn = "More about Node64"; $node64_hint_href = "/node64.php?lang=en"; include("node64_hint.php"); ?>
```

## v64_secure.php (optional)

Anker (Zeile ~155, einziges Vorkommen, Abschluss-Masthead unten):

```html
<div class="bd-masthead mb-3" id="content">
```

**Davor** einfügen (eigener Container, weil der Seiteninhalt darüber schon geschlossen ist):

```php
	<div class="container"><?php $node64_hint = "Instant blocking in PROXY64 and an nftables helper – Honeypot64 and the v64 Blocklist work hand in hand in Node64."; $node64_hint_btn = "More about Node64"; $node64_hint_href = "/node64.php?lang=en"; include("node64_hint.php"); ?></div>
```

---

## Später: Startseite (index.php) – NICHT jetzt

Anker (Zeile ~13, einziges Vorkommen, direkt unter dem Jumbotron):

```html
	<div class="container pt-4">
```

**Danach** einfügen:

```php
	<?php $node64_hint = "New: Node64 – health checks, reverse proxy, DNS filter, DynDNS and honeypot in your home network, connected to your ipv64 account."; $node64_hint_btn = "More about Node64"; $node64_hint_href = "/node64.php?lang=en"; include("node64_hint.php"); ?>
```

## Später: Menüpunkt „Node64“ in header.php – NICHT jetzt

Anker (Navigation, einziges Vorkommen):

```html
			  <a class="nav-link text-dark" alt="Statistics - IPv64.net" href="https://statistics.ipv64.net" target="_blank">Statistics</a>
```

Die `<li class="nav-item">` dieses Eintrags beginnt eine Zeile darüber – **vor** dieser `<li>` einfügen:

```html
			<li class="nav-item">
			  <a class="nav-link text-dark" alt="Node64 - IPv64.net" href="https://ipv64.net/node64.php"><img src="/img/node64/node64_icon.png" height="18" alt="" class="mb-1"> Node64</a>
			</li>
```

Optional Seitentitel (Kette `if($fullurl == …) … elseif(str_contains($fullurl, …))` in header.php, z. B. direkt
vor `}elseif(str_contains($fullurl,"/nodes")){`):

```php
		}elseif(str_contains($fullurl,"/node64.php")){
		$title = "<title>Node64 &#8226; The homelab container by IPv64.net</title>";
```
