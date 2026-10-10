# Phase 1 – Änderungen am Webcode (Vorher/Nachher)

**Grundsatz (Entscheidung Dennis, 2026-10-10): keine Migration.** Wer in die neue Healthcheck-Welt wechselt, fängt bei null an. Die alte Welt (Tabellen, Bots, Seiten) bleibt **komplett unverändert** und läuft für alle weiter, bis sie am Ende abgeschaltet wird. Das Flag `users.hc2` merkt sich nur, dass ein Nutzer die neue Welt aktiviert hat (Menü).

Damit sind es nur noch zwei Eingriffe, beide ohne Wirkung auf Bestehendes.

## 1. `dbconnect.php` – hc2-Block anhängen

Den Inhalt von `dbconnect_hc2.php` (ohne die erste Zeile `<?php`) **ans Ende** von `dbconnect.php` anhängen. Wer den früheren Block schon drin hat: den Block ab der Kommentarzeile „Healthchecks 2.0 (hc2)“ bis zum Dateiende durch den aktuellen ersetzen.

Drei Dateien außerhalb des Webroots (Pfade stehen oben im Block; `chmod 640`, Besitzer wie der Webroot):

```bash
# Schluessel fuer Kanal-Geheimnisse: 32 Rohbytes, identisch auf Web-Server und beiden hubs
head -c 32 /dev/urandom > /var/www/clients/client1/web58/private/hc2_secret.key
# Redis-Passwort (Inhalt von /etc/ipv64-hub/redis.pass auf hc-srv02)
#   -> /var/www/clients/client1/web58/private/hc2_redis.pass
# Passwort des MySQL-Benutzers ipv64_hc, eine Zeile, ohne Anfuehrungszeichen
#   -> /var/www/clients/client1/web58/private/hc2_db.pass
```

Die Schlüsseldatei anschließend auf hc-srv01 nach `/root/hc2_secret.key` legen – ich verteile sie auf beide hubs.

## 2. `health.php` – Heartbeats der neuen Welt annehmen

Push-Checks der neuen Welt bekommen neue Tokens, die es in `healthchecks` nicht gibt. Damit `https://ipv64.net/health.php?token=…` auch für sie funktioniert (gleiche URL wie bisher), **eine Zeile** direkt nach der Token-Prüfung einfügen. Für alte Tokens liefert die Funktion `false`, und alles läuft wie bisher.

Vorher (ca. Zeile 50):
```php
if(isset($key) AND $key != "" AND strlen($key) == "32")
{
```
Nachher:
```php
if(isset($key) AND $key != "" AND strlen($key) == "32")
{
	if (hc2_push($key, $_GET + $_POST)) { http_response_code(200); echo "OK"; exit; }
```

Optional für `maintenance`/`start` der neuen Welt: `?status=down&msg=…` meldet eine Störung, sonst zählt der Aufruf als „OK“. Pausieren geht in der neuen Welt über die Oberfläche/API.

## Rückbau der früheren Schritte (falls schon eingespielt)

Die früher beschriebenen Ein-Zeilen-Änderungen sind **nicht mehr nötig** und sollten zurückgenommen werden, damit die alte Welt wirklich unberührt bleibt:

- `bots/healthcheck_web_live.php`, `healthcheck_tcp_live.php`, `healthcheck_pings_live.php`: die Zeile `AND u.hc2 = 0` wieder entfernen.
- `dbconnect.php`, `healthcheck_check()`: die beiden Abfragen wieder auf `SELECT * FROM healthchecks WHERE status = 3 AND type = 'health'` bzw. `... WHERE alarm_time <= NOW() AND status = 1 AND type = 'health'` zurücksetzen.
- `health.php`: die Zeile `hc2_push_mirror(...)` entfernen (ersetzt durch Schritt 2).
- `bots/hc2_migrate.php`: löschen, falls kopiert.

## Prüfen

- `php -l dbconnect.php` ohne Fehler; Portal-Seiten laden wie vorher.
- Ein Heartbeat auf `health.php?token=<alter Token>` verhält sich exakt wie bisher.
- `health.php?token=<unbekannt>` liefert wie bisher die alte Antwort (nichts verrät, ob ein Token in der neuen Welt existiert).
