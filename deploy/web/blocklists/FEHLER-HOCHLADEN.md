# Blocklisten: Fehler behoben (Tor, Gesamtliste ohne Tor, Länder, Listenseite, tote Links)

## Was sich ändert

- **Tor:** Beide Listen kommen direkt vom Tor-Projekt (Onionoo) statt vom Checkpoint-Spiegel, jetzt mit IPv6.
  Getestet am 19.10.: alle Relays 9.621 Adressen (2.978 IPv6), Exit-Knoten 2.100 (910 IPv6). Bisher kam kein IPv6 an.
- **Gesamtliste ohne Tor:** neu `ipv64_blocklist_all_notor.txt` (+ `_v4_`, `_v6_`, MikroTik `_all_notor.rsc`). „all“
  bleibt wie bisher (mit Tor) und ist auf der Seite so gekennzeichnet.
- **MikroTik:** jede Datei mit eigenem Listennamen `IPv64-<id>` (siehe LEITFADEN-HOCHLADEN.md).
- **Länder:** neues Skript `read_countries_rir.php` lädt täglich die offiziellen Zuteilungsdaten der fünf
  Registrierungsstellen (RIR) statt der festen `global.json` vom März 2024. Getestet: 239 Länder, 334.750 Netze
  (DE 14.200, US 81.358). Regionen neu: Südamerika und Ozeanien.
- **read_blocklists.php:** Timeout 10 → 60 s (Onionoo und große Listen), toter Code bei Spamhaus entfernt, keine
  Ausgabe der kompletten Spamhaus-Liste mehr ins Cron-Log.
- **Listenseite `v64_blocklists.php`:**
  - Status nach Alter: älter als 2 Tage = „Outdated“, statt fest „Ok“.
  - Anzahl und Stand der Gesamtliste und der Kontinente aus den Dateien (bisher Summe der Einzellisten bzw. „-/-“
    und das Datum der zuletzt gelesenen Liste).
  - Neue Zeilen: „All lists without Tor“, Südamerika, Ozeanien.
  - Text korrigiert: Statt „false positive entries have been removed“ steht dort jetzt, was wirklich entfernt
    wird, und wer bei Fehlalarmen zuständig ist. Tippfehler „Comming“ und „Futher“.

Den genauen Unterschied zeigt Git: `git diff 689de72 -- deploy/web/blocklists/site`.

## 1. Dateien hochladen

| Datei im Repo | Ziel auf dem Webserver |
|---|---|
| `deploy/web/blocklists/site/bots/blocklist/read_blocklists.php` | `bots/blocklist/read_blocklists.php` |
| `deploy/web/blocklists/site/bots/blocklist/create_blocklists_v2.php` | `bots/blocklist/create_blocklists_v2.php` |
| `deploy/web/blocklists/bots/read_countries_rir.php` | `bots/blocklist/read_countries_rir.php` (neu) |
| `deploy/web/blocklists/site/v64_blocklists.php` | `v64_blocklists.php` |

## 2. SQL (Tor-Quellen)

```sql
UPDATE blocklisten SET url = 'https://onionoo.torproject.org/details?type=relay&running=true&fields=or_addresses'
 WHERE file_name = 'tor_all';
UPDATE blocklisten SET url = 'https://onionoo.torproject.org/details?type=relay&running=true&flag=Exit&fields=or_addresses,exit_addresses'
 WHERE file_name = 'tor_exit';
```

## 3. Cron für die Länder (täglich, vor dem Generator)

```
20 3 * * * php /var/www/clients/client1/web58/web/bots/blocklist/read_countries_rir.php > /dev/null
```

Zuerst einmal von Hand mit `--dry` starten: Es lädt nur und zeigt die Statistik, ohne die Datenbank zu ändern.
Ohne `--dry` ersetzt es `bl_countries_ips` in einer Transaktion. Fällt eine Registrierungsstelle aus oder kommen
zu wenige Netze an, bleibt alles unverändert. Danach schreibt der nächste Lauf von `create_blocklists_v2.php` die
Länderdateien neu.

## 4. Tote Links zum „v64 Blocker“

Die Dateien `v64.txt`, `v64_spamhaus.txt`, `v64_firehol_l1.txt` und `v64_blde_all.txt` gibt es nicht (404). Der Block
ist in drei Dateien gleich: `blocklistv64.php`, `blocklist_node_edit.php` und `api_settings.php`.

### Vorher

```html
				<ul>
					<li>v64 Blocklist (<a href="https://ipv64.net/blocklists/v64.txt" target="_blank">https://ipv64.net/blocklists/v64.txt</a>)</li>
				</ul>
```

### Nachher

```html
				<ul>
					<li>v64 Blocklist: <em>not available at the moment</em></li>
				</ul>
```

### Vorher

```html
					<li>Spamhaus DROP + EDROP + v64 Blocklist (<a href="https://ipv64.net/blocklists/v64_spamhaus.txt" target="_blank">https://ipv64.net/blocklists/v64_spamhaus.txt</a>)</li>
					<li>Firehole Level 1 + v64 Blocklist (<a href="https://ipv64.net/blocklists/v64_firehol_l1.txt" target="_blank">https://ipv64.net/blocklists/v64_firehol_l1.txt</a>)</li>
					<li>Blocklist.de All + v64 Blocklist (<a href="https://ipv64.net/blocklists/v64_blde_all.txt" target="_blank">https://ipv64.net/blocklists/v64_blde_all.txt</a>)</li>
```

### Nachher

```html
					<li>Spamhaus DROP (<a href="https://ipv64.net/blocklists/ipv64_blocklist_spamhaus_drop.txt" target="_blank">https://ipv64.net/blocklists/ipv64_blocklist_spamhaus_drop.txt</a>)</li>
					<li>FireHOL Level 1 (<a href="https://ipv64.net/blocklists/ipv64_blocklist_firehole_l1.txt" target="_blank">https://ipv64.net/blocklists/ipv64_blocklist_firehole_l1.txt</a>)</li>
					<li>Blocklist.de All (<a href="https://ipv64.net/blocklists/ipv64_blocklist_blocklistde_all.txt" target="_blank">https://ipv64.net/blocklists/ipv64_blocklist_blocklistde_all.txt</a>)</li>
```

## 5. Sicherheit (unabhängig davon)

In `bots/dns64_bot.php` Zeile 15 steht ein Basic-Auth-Wert im Klartext. Bitte ändern und aus dem Code nehmen, z. B.
in eine Datei außerhalb des Webroots.

## Prüfen

- `php bots/blocklist/read_countries_rir.php --dry` zeigt rund 239 Länder und über 300.000 Netze.
- Nach `read_blocklists.php` und `create_blocklists_v2.php`:
  - `curl -s https://ipv64.net/blocklists/ipv64_blocklist_v6_tor_exit.txt | wc -l` ist größer als 0.
  - `curl -sI https://ipv64.net/blocklists/ipv64_blocklist_all_notor.txt` liefert 200.
  - `curl -s https://ipv64.net/blocklists/countries/ipv64_blocklist_oceania.txt | head -3` zeigt Netze.
- Listenseite: alle Zeilen „Ok“, Gesamtliste mit echter Anzahl, neue Zeilen vorhanden.
