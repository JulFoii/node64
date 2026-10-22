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

## KI-Bots (2026-10-22): zwei Listen, ohne SQL und ohne neuen Cron

Beide Listen schreibt `create_blocklists_v2.php` im vollen Lauf über `bots/blocklist/ai_bots.php` (eingebunden, fehlt
die Datei, läuft alles wie bisher). Quellen werden höchstens alle 20 Stunden geladen (`--ai-refresh` erzwingt es). Je
Quelle liegt die letzte gültige Fassung in `private/blocklists_ai/` (neben `web/`); fällt eine Quelle aus oder liefert
Unsinn, gilt die alte weiter. Liefert keine Quelle etwas, bleiben die Dateien unverändert. Kostenlos wie alle Listen,
nicht in `all`.

| ID | Inhalt | Dateien unter `blocklists/` | index.json |
|---|---|---|---|
| `ai_bots` | v64 AI Bots (IP): offizielle Netze der Betreiber, IPv4 + IPv6, Duplikate und enthaltene Netze entfernt (Test: 310 Netze) | `ipv64_blocklist_ai_bots.txt`, `_v4_`, `_v6_`, MikroTik `IPv64-ai_bots`, `ipv64_blocklist_ai_bots_sources.txt` (Netz `#` Quellen) | `lists`, Kategorie `ai`, je Quelle `sources` (Art, Nutzer-Abruf, Anzahl, Stand, ok/Fehler) |
| `ai_useragents` | v64 AI Bots (User-Agent): Spiegel von ai.robots.txt (MIT), Test: 193 Kennungen, 53 Nutzer-Abrufe | `ipv64_ai_useragents.txt` (eine je Zeile), `ipv64_ai_useragents.json` (Betreiber, Zweck, Beschreibung, `user`), `ipv64_ai_robots.txt` | `data` (keine IP-Liste), Kategorie `ai` |

Quellen der IP-Liste (alle `{"prefixes":[{"ipv4Prefix"|"ipv6Prefix"}]}`): OpenAI `gptbot.json`, `searchbot.json`,
`chatgpt-user.json` (Nutzer); Perplexity `perplexitybot.json`, `perplexity-user.json` (Nutzer); Common Crawl
`ccbot.json`; Mistral `mistralai-user-ips.json` (Nutzer); Google `user-triggered-agents.json` (Google-Agent, Nutzer).
Prüfung: gültiges JSON, höchstens 5.000 Einträge, Netz parsebar, nicht kleiner als /16 bzw. /32, keine privaten
Bereiche.

Nicht aufgenommen: Googlebot/Google-Extended, Bingbot und Applebot/Applebot-Extended (Netze mit der normalen Suche
geteilt; Extended ist nur ein robots.txt-Name), DuckAssistBot (`duckassistbot.json` ist dieselbe Datei wie
`duckduckbot.json`), Amazonbot (nur HTML-Seite, dient auch Alexa), ClaudeBot, Meta, Bytespider (keine
maschinenlesbare Liste). Über die User-Agent-Liste sind sie trotzdem erfasst.

User-Agent-Liste: Kennungen nur druckbares ASCII, 3–80 Zeichen, ohne `" ' \ # ; < > { } | ^ * $`; weniger als 50
gültige = Quelle ungültig. `user` = Funktion „AI Assistants/Agents/Coding Agents“, Name endet auf `User` oder Text
nennt Nutzer-Prompts.

Hochladen: `site/bots/blocklist/ai_bots.php` → `bots/blocklist/ai_bots.php` (neu),
`site/bots/blocklist/create_blocklists_v2.php` → `bots/blocklist/create_blocklists_v2.php`,
`site/v64_blocklists.php` → `v64_blocklists.php`. Danach einmal `php bots/blocklist/create_blocklists_v2.php --ai-refresh`.

Prüfen: `curl -s https://ipv64.net/blocklists/ipv64_blocklist_ai_bots.txt | wc -l` (rund 300),
`curl -s https://ipv64.net/blocklists/ipv64_ai_useragents.txt | wc -l` (rund 190), in `index.json` `ai_bots`
unter `lists` und `ai_useragents` unter `data`.
