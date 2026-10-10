# Phase 1 – Änderungen am Webcode (Vorher/Nachher)

Alles minimal, alte Seiten und Bots laufen unverändert weiter, solange `users.hc2 = 0` ist (Standard). Reihenfolge: 1 → 2 → 3 → 4. Nichts davon braucht den hub.

## 1. `dbconnect.php` – hc2-Hilfsfunktionen anhängen

Den Inhalt von `dbconnect_hc2.php` (ohne die erste Zeile `<?php`) **ans Ende** von `dbconnect.php` anhängen. Neue Funktionen: `hc2_log_change()`, `hc2_signal()`, `hc2_push_mirror()`, `hc2_encrypt()`/`hc2_decrypt()`. Sie nutzen `connectRedis()` aus derselben Datei.

Dazu zwei Dateien außerhalb des Webroots (Pfad in den Konstanten oben im Block anpassen, falls anders):

```bash
# Schluessel fuer Kanal-Geheimnisse: 32 Rohbytes, identisch auf Web-Server und beiden hubs
head -c 32 /dev/urandom > /var/www/clients/client1/web58/private/hc2_secret.key
chmod 640 /var/www/clients/client1/web58/private/hc2_secret.key
```

```bash
# Redis-Passwort (Inhalt von /etc/ipv64-hub/redis.pass auf hc-srv02)
# -> /var/www/clients/client1/web58/private/hc2_redis.pass (chmod 640)
```

Die Schlüsseldatei kopiere ich anschließend auf beide hubs nach `/var/lib/ipv64-hub/secret.key` (sag Bescheid, wenn sie liegt – oder lege sie auf hc-srv01 unter `/root/hc2_secret.key` ab, dann verteile ich sie).

## 2. Alte Bots überspringen `hc2`-Accounts

Je eine Zeile in der Auswahlabfrage. `users` ist dort bereits gejoint (`u`).

**`bots/healthcheck_web_live.php`** (ca. Zeile 215)

Vorher:
```php
        WHERE h.type IN ('web','keyword')
          AND h.status != 2
```
Nachher:
```php
        WHERE h.type IN ('web','keyword')
          AND u.hc2 = 0
          AND h.status != 2
```

**`bots/healthcheck_tcp_live.php`** (ca. Zeile 292)

Vorher:
```php
        WHERE h.type = 'tcp'
          AND h.status != 2
```
Nachher:
```php
        WHERE h.type = 'tcp'
          AND u.hc2 = 0
          AND h.status != 2
```

**`bots/healthcheck_pings_live.php`** (ca. Zeile 235)

Vorher:
```php
        WHERE h.type = 'ping'
          AND h.status != 2
```
Nachher:
```php
        WHERE h.type = 'ping'
          AND u.hc2 = 0
          AND h.status != 2
```

**`dbconnect.php`, Funktion `healthcheck_check()`** – Push-Watchdog, zwei Abfragen (ca. Zeile 1392 und 1446)

Vorher:
```php
	$statement = $pdo->prepare("SELECT * FROM healthchecks WHERE status = 3 AND type = 'health'");
```
Nachher:
```php
	$statement = $pdo->prepare("SELECT h.* FROM healthchecks h JOIN users u ON u.id = h.userid WHERE u.hc2 = 0 AND h.status = 3 AND h.type = 'health'");
```

Vorher:
```php
	$statement = $pdo->prepare("SELECT * FROM healthchecks WHERE alarm_time <= NOW() AND status = 1 AND type = 'health'");
```
Nachher:
```php
	$statement = $pdo->prepare("SELECT h.* FROM healthchecks h JOIN users u ON u.id = h.userid WHERE u.hc2 = 0 AND h.alarm_time <= NOW() AND h.status = 1 AND h.type = 'health'");
```

(Die alten Bots `healthcheck_web.php`, `healthcheck_tcp.php`, `healthcheck_pings.php` ohne `_live` sind die Vorgänger; falls sie noch im Cron stehen, dieselbe Bedingung – sonst nichts tun.)

## 3. `health.php` – Heartbeat nach hc2 spiegeln

Direkt nach dem Laden des Checks (ca. Zeile 56, nach `$healthcheck = $statement->fetch();`) **eine Zeile** einfügen. Alte Logik bleibt komplett; die Funktion tut nur etwas, wenn der Besitzer `hc2 = 1` hat.

Vorher:
```php
	$statement = $pdo->prepare("SELECT * FROM healthchecks WHERE BINARY healthtoken = :key");
	$result = $statement->execute(array('key' => $key));
	$healthcheck = $statement->fetch();
```
Nachher:
```php
	$statement = $pdo->prepare("SELECT * FROM healthchecks WHERE BINARY healthtoken = :key");
	$result = $statement->execute(array('key' => $key));
	$healthcheck = $statement->fetch();
	hc2_push_mirror($pdo, $healthcheck, $_GET);
```

## 4. Migrationsskript

`bots/hc2_migrate.php` nach `bots/` kopieren (nur CLI, kein Cron). Testlauf:

```bash
php /var/www/clients/client1/web58/web/bots/hc2_migrate.php test@schroederdennis.de --dry-run
```

Dann echt, aber noch **ohne** Aktivierung (Account bleibt im alten System, Daten liegen in `ipv64_hc`):

```bash
php /var/www/clients/client1/web58/web/bots/hc2_migrate.php test@schroederdennis.de
```

`--activate` erst, wenn der hub läuft (Phase 2). Ein zweiter Lauf ändert nichts (idempotent). Das Skript braucht `hc2_secret.key` aus Schritt 1, sobald der Account Integrationen mit Geheimnissen hat.

## 5. Rechte für den Portal-Benutzer

Der MySQL-Benutzer aus `dbconnect.php` braucht Rechte auf die neue Datenbank:

```sql
GRANT SELECT, INSERT, UPDATE, DELETE ON `ipv64_hc`.* TO '<portal-benutzer>'@'localhost';
FLUSH PRIVILEGES;
```

## Prüfen

- `php -l dbconnect.php` ohne Fehler; Portal-Seiten laden wie vorher.
- Dry-run des Migrationsskripts zeigt plausible Zahlen (Kanäle, Checks, Messpunkte).
- Nach dem echten Lauf: `SELECT COUNT(*) FROM ipv64_hc.hc2_checks WHERE userid = <id>;` entspricht der Zahl in `healthchecks`.
- Ein Heartbeat auf `health.php?token=...` eines Testchecks läuft wie bisher (Account noch `hc2 = 0`, also keine Spiegelung).
