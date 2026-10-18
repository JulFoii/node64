# T8 – Portmapper und Abschaltung des alten CDN (ipv64.net)

Teil A gehört zum Portmapper und kann sofort eingespielt werden. Teil B ist die Ankündigung im alten CDN (Datum legst
du fest). Teil C erst nach Ablauf der Frist.

## Teil A – Portmapper (jetzt)

1. **SQL:** aus `deploy/sql/cdn64_online.sql` den Block `-- T8: Portmapper` ausführen (neue Tabelle
   `cdn64o_mappings`; die Datei ist weiterhin mehrfach ausführbar).
2. **`api_v2_cdn64o.php`** ersetzen. Neu:
   - `GET|POST /cdn64o/hosts/{id}/mappings`, `DELETE /cdn64o/hosts/{id}/mappings/{mid}` (nur Modus 3);
   - Limit `user_class.cdn_mappings`, altes CDN (`cdn_mapping`) zählt mit; Kontingent `quota.mappings`;
   - Ports der Server 50000–62000 wie beim alten CDN: liegt der Ziel-Port im Bereich und ist frei, wird er genommen,
     sonst derselbe wie ein anderes Mapping des Namens auf diesen Ziel-Port (TCP und UDP gleich), sonst zufällig;
   - `frontend: 0` = keine Webseite, nur Portmapper (wie „Proxy aus, Portmapper an“ im alten CDN);
   - die Server bekommen die Mappings in `edge/config`; Ausschalten eines Namens löscht seine Mappings.
3. **`cdn64.php`** ersetzen: Karte „Port mappings (TCP/UDP)“ in der Bearbeiten-Ansicht eines Modus-3-Namens,
   Stufe „Off: no website, port mappings only“, Anzahl im Kontingent und in der Liste.
4. **Server (srv07/srv08):** `cdn64-edge` 0.8.0 und Firewall 50000–62000 TCP/UDP – rolle ich nach deinem Go aus.

## Teil B – Ankündigung im alten CDN (`cdn.php`)

### B1. Hinweis über der Liste der CDN-Domains

VORHER:

```php
				<?php echo $cdn_info; ?>
```

NACHHER (Datum anpassen):

```php
				<div class="alert alert-warning m-2" role="alert">
					<b>The old CDN will be switched off on 2026-12-31.</b> Please set up your domains again in
					<a href="cdn64">CDN64</a> (two servers, IPv4 &amp; IPv6, reverse proxy, cache, allow/block list and port mapper).
					With <a href="https://github.com/ipv64net/node64" target="_blank" rel="noopener">Node64</a> it works without open ports.
					After that date your DNS records point to your own addresses again.
				</div>
				<?php echo $cdn_info; ?>
```

### B2. Keine neuen Domains mehr im alten CDN (empfohlen ab der Ankündigung)

VORHER:

```php
		if(isset($_GET["add_cdn"]) AND $cdn_domain != "") {
```

NACHHER:

```php
		if(isset($_GET["add_cdn"]) AND $cdn_domain != "") { $cdn_info = "<div class=\"alert alert-warning\" role=\"alert\">The old CDN takes no new domains. Please use <a href=\"cdn64\">CDN64</a>.</div>"; }
		if(false AND isset($_GET["add_cdn"]) AND $cdn_domain != "") { // altes CDN: keine neuen Domains (T8)
```

## Teil C – nach der Frist

Wichtig: Der Löschlauf in `bots/cdn_bot.php` (`dell = 1`) löscht **alle** Einträge mit dem CDN-Token – auch die
deaktivierten Originale der Kunden. Deshalb nicht einfach alle Domains auf `dell = 1` setzen, sondern:

1. `bots/cdn_alt_abschalten.php` (aus diesem Ordner) nach `bots/` kopieren. Es setzt je Domain zuerst die DNS zurück
   (CDN-Einträge `cdn_tmp` 1/2 weg, Originale wieder aktiv, `do_zone_update` je Name und Typ mit der TTL des Originals)
   und setzt erst dann `dell = 1`. Die alten Server müssen dabei noch laufen und `cdn_bot.php` weiter als Cron.
   ```
   php bots/cdn_alt_abschalten.php                  # nur anzeigen
   php bots/cdn_alt_abschalten.php --domain=<id> --run   # eine Testdomain (subdomains.id)
   php bots/cdn_alt_abschalten.php --run            # alle
   ```
2. Prüfen, wenn `cdn_bot.php` durch ist (beides muss 0 sein):
   ```sql
   SELECT count(*) FROM cdn_domains;
   SELECT count(*) FROM subdomain_records WHERE cdn_tmp IN (1, 2) OR (cdn_token NOT IN ('0', '1') AND cdn_tmp = 0);
   ```
3. `cdn.php` auf die neue Seite umleiten (ganz oben, vor dem `include`):

   VORHER:

   ```php
   <?php 
   include("header.php");
   ```

   NACHHER:

   ```php
   <?php 
   header("Location: https://ipv64.net/cdn64", true, 301); exit; // altes CDN abgeschaltet (T8)
   include("header.php");
   ```
4. Crons des alten CDN abschalten (`cdn_bot.php`, `cdn_bot_le.php`, `cdn_server_move.php`, `cdn_traffic.php`,
   `cdn_alt_loeschen.php`, `cdn_vpn_traffic_delete.php`), dann srv01–srv06 abschalten.
   `portmapper_bot.php` / `portmapper.php` (Tabelle `cdn_portmapper`) gehören zum alten Einzel-Portmapper – falls der
   noch läuft, gilt dasselbe.
5. Das Kontingent (`cdn_domains`, `cdn_mappings`) zählt danach automatisch nur noch CDN64, weil `cdn_domains` und
   `cdn_mapping` leer sind. Der Traffic des alten CDN (`users.cdn_traffic_input/output`) zählt bis zum Monatsende mit.

## Abgleich: altes CDN → CDN64 Modus 3

| Altes CDN | CDN64 |
|---|---|
| Reverse Proxy an/aus | Modus 3, Stufe 0 (aus, nur Ports) bis 3 |
| Backend HTTP/HTTPS + Port | Ziel: Schema, Port, Zertifikat prüfen ja/nein, IPv6 bevorzugt |
| Frontend 1/2/3 | Stufen 1/2/3 (gleiche Bedeutung) |
| Let's Encrypt anfordern | automatisch (DNS-01, Wildcard), keine Aktion nötig |
| WebSockets an/aus | immer an |
| Cache (Zeit, Größe) | Schalter, Größe nach Klasse, richtet sich nach `Cache-Control` |
| IP-Sperrliste / Default | Erlauben-/Sperrliste (alle Modi) |
| Portmapper TCP/UDP | Portmapper TCP/UDP, Ports 50000–62000 |
| Records auswählen | je Name ein Eintrag (Ziel = A/AAAA des Namens, DynDNS hält sie aktuell, oder fest) |
| CDN-Server wechseln | entfällt: immer zwei Server, Ausfall automatisch |
| Konfiguration neu erzeugen | entfällt: Server holen alle 10 s |
| Traffic zurücksetzen | entfällt: Traffic je Monat |
| Echte Besucher-IP | `X-Forwarded-For` / `X-Real-IP` (HTTP); beim Portmapper sieht das Ziel die Server-Adresse (wie bisher) |
