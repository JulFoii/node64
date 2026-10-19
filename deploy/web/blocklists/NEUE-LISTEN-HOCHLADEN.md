# Blocklisten: neue Listen und index.json

Baut auf FEHLER-HOCHLADEN.md auf (die Dateien dort enthalten diese Änderungen schon mit, falls sie noch nicht
hochgeladen sind: einfach den aktuellen Stand nehmen).

## Was neu ist

Acht neue Listen. Die Gesamtliste `all` wächst nur um die zwei kleinen und sehr sicheren:

| ID | Inhalt | in `all` | Lizenz |
|---|---|---|---|
| `feodo` | Botnet-Steuerserver (abuse.ch Feodo Tracker) | ja | CC0 |
| `et_compromised` | kompromittierte Hosts (Emerging Threats), ca. 500 | ja | ET Open |
| `cins_army` | CINS Army, 15.000 Adressen | nein | laut CINS frei nutzbar, keine formale Lizenz |
| `ipsum_l3` | IPsum, auf mind. 3 Sperrlisten, ca. 19.000 | nein | Unlicense |
| `doh_servers` | DoH-Server (zum Sperren ausgehend), IPv4 + IPv6 | nein | GPL-3.0 |
| `cloudflare` | Cloudflare-Netze (Freigabeliste) | nein | Angabe des Anbieters |
| `aws` | alle AWS-Netze | nein | Angabe des Anbieters |
| `gcp` | Google-Cloud-Kundennetze | nein | Angabe des Anbieters |

Neu ist außerdem `blocklists/index.json`. Der Generator schreibt sie bei jedem Lauf. Sie enthält jede Liste mit Kategorie,
Anzahl (v4/v6), Stand, Quelle, Lizenz und Dateinamen, dazu die Gesamtlisten, Länder und Kontinente. Node64 baut
daraus später seine Auswahl.

Feodo Tracker ist zurzeit fast leer (abuse.ch nennt die Datensätze derzeit leer, im Test 1 Eintrag). Die Liste bleibt trotzdem
drin, weil sie bei neuen Botnetzen sofort wieder Einträge hat.

DShield steht unter CC BY-NC-SA (nicht kommerziell). Das war schon bisher so; nur zur Info, falls ipv64 die Listen einmal
kostenpflichtig anbietet.

Getestet am 19.10. mit einer Kopie des Schemas aus dem Dump (MariaDB 10.5, PHP 8.3): SQL läuft durch, alle 14 Listen
werden gelesen (42 s), der Generator schreibt alle Dateien und eine gültige index.json, jede darin genannte Datei
existiert. Ein fehlgeschlagener Download lässt die alte Liste stehen. Ohne die neuen Spalten verhält sich der Generator
wie bisher.

## 1. SQL (zuerst)

`deploy/web/blocklists/sql/blocklists_neue_listen.sql` einspielen. Es legt fünf Spalten in `blocklisten` an, beschreibt
die sechs bestehenden Listen, legt acht Tabellen `bl_*` an und trägt die neuen Listen ein.

## 2. Dateien hochladen

| Datei im Repo | Ziel auf dem Webserver |
|---|---|
| `deploy/web/blocklists/site/bots/blocklist/read_blocklists.php` | `bots/blocklist/read_blocklists.php` |
| `deploy/web/blocklists/site/bots/blocklist/create_blocklists_v2.php` | `bots/blocklist/create_blocklists_v2.php` |
| `deploy/web/blocklists/site/v64_blocklists.php` | `v64_blocklists.php` |
| `deploy/web/blocklists/v64_blocklist_integration_guide.php` | `v64_blocklist_integration_guide.php` |

Cron bleibt wie er ist.

## Prüfen

- `php bots/blocklist/read_blocklists.php` meldet keine „Download fehlgeschlagen“.
- `php bots/blocklist/create_blocklists_v2.php` endet mit `index.json: 14 Listen, … Laender`.
- `curl -s https://ipv64.net/blocklists/index.json | head -20` zeigt JSON.
- `curl -s https://ipv64.net/blocklists/ipv64_blocklist_cloudflare.txt | head -3` zeigt Netze.
- Listenseite: neue Zeilen mit Beschreibung; Cloud und DoH tragen „not in All“.
