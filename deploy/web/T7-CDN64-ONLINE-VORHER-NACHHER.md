# CDN64 online – Phase T7 einspielen (ipv64.net)

Modus 3 (direkt zum Ziel, ohne Node) und die neue Seite **cdn64.php**. Getestet in der Testumgebung (API 86 Prüfungen,
Seite 10 Prüfungen) und mit Go-Tests der Server.

## 1. SQL (Hauptdatenbank ipv64)

Der neue Block am Ende von `deploy/sql/cdn64_online.sql` (die ganze Datei geht auch, sie ist mehrfach ausführbar):
Tabellen `cdn64o_targets` und `cdn64o_acl`, Spalte `cdn64o_hosts.acl_default`.

## 2. Dateien

- `deploy/web/api_v2_cdn64o.php` über die vorhandene Datei kopieren (`api_v2.php` bleibt unverändert).
- `deploy/web/cdn64.php` neu in den Webroot (neben `cdn.php`). Die Seite ruft serverseitig die API v2 mit dem
  Account-Key des angemeldeten Nutzers auf (`users.apikey`, wird beim Login erzeugt) – dieselben Prüfungen wie
  API und Node. PHP braucht dafür ausgehend HTTPS zu `https://ipv64.net/api/v2`.

## 3. `header.php`: Menüeintrag

VORHER (Menü „CDN“):

```php
					<a class="dropdown-item" alt="CDN Service" href="https://ipv64.net/cdn"><i class="fa-solid fa-building-shield fa-sm"></i> CDN Service</a>
```

NACHHER:

```php
					<a class="dropdown-item" alt="CDN64" href="https://ipv64.net/cdn64"><i class="fa-solid fa-cloud-arrow-up fa-sm"></i> CDN64 (neu)</a>
					<a class="dropdown-item" alt="CDN Service" href="https://ipv64.net/cdn"><i class="fa-solid fa-building-shield fa-sm"></i> CDN Service</a>
```

## Was neu ist

- **Modus 3:** `POST /cdn64o/hosts` mit `mode: 3` (ohne Tunnel) und Ziel: `source` = `records` (die bisherigen A/AAAA des
  Namens – DynDNS aktualisiert sie weiter, die Server bekommen jede Änderung mit der Konfiguration, also in Sekunden)
  oder `fixed` (`target` = öffentliche IP oder Name), `scheme` http/https, `port`, `verify_tls`, `prefer_ipv6`,
  `frontend` (1 nur HTTP, 2 HTTPS mit Umleitung, 3 nur HTTPS), `cache_mb` (bis `user_class.cdn_cache_size`),
  `cache_minutes`. Ändern mit `PUT /cdn64o/hosts/{id}/target`.
- **Liste** (alle Modi): `GET|PUT /cdn64o/hosts/{id}/acl` `{default: off|allow|deny, list: [IP oder Netz]}` wie die
  White-/Blacklist des alten CDN.
- **Ziele nur öffentlich:** keine privaten, CGNAT-, Dokumentations-, Loopback- oder Server-eigenen Adressen; die Server
  prüfen zusätzlich bei jeder Verbindung (auch nach dem Auflösen eines Namens).
- Wechsel zwischen Modus 3 und 1/2 geht nicht per PATCH (aus- und wieder einschalten).
