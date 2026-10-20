# Honeypot64 – Phase H4, DNS-Sperrliste `bl.ipv64.net` einspielen (ipv64.net)

DNSBL nach dem Muster von Spamhaus (RFC 5782) aus dem **Tagesstand der v64 Blocklist**: Mailserver (Postfix, rspamd,
SpamAssassin) fragen `4.3.2.1.bl.ipv64.net` ab und bekommen `127.0.0.x` je Art plus einen TXT mit Grund und Link zur
IP-Auskunft. Planung: `docs/PLAN-NODE64-HONEYPOT64.md` (Abschnitte 7, 8, H4). Voraussetzung: H3 (Bewertung + Listen,
Freigaben) ist eingespielt und der Tagesstand `blocklists/ipv64_blocklist_v64*.txt` entsteht.

Getestet in einer abgeschotteten Testumgebung auf der Testbox: 84 Prüfungen der Logik (SQLite, `zone_update` als
Stub) und 23 Prüfungen gegen einen lokalen PowerDNS 4.9 mit echten Abfragen per `sdig`, alle grün
(`deploy/web/honeypot/tests/h4_dnsbl/run_agentbox.sh`).

## Vorher / Nachher

| | Vorher | Nachher |
|---|---|---|
| DNS-Sperrliste | gibt es nicht | Zone `bl.ipv64.net` mit allen IPs des Tagesstands (ohne research), TTL 300 |
| Datenbank | – | neue Tabelle `hp_dnsbl` (Zustand des Abgleichs), sonst nichts geändert |
| Dateien | – | neu: `bots/honeypot_dnsbl.php` (Cron); **keine bestehende Datei geändert** |
| PowerDNS | – | neue Zone `bl.ipv64.net` (Master + Slave), in `ipv64.net` ein NS-RRset `bl` |
| Cron | – | stündlich `honeypot_dnsbl.php` (schreibt nur Unterschiede) |

## Rückgabecodes

Jede gelistete IP bekommt **immer** `127.0.0.2`, dazu je Teilliste einen weiteren A-Record (mehrere Antworten
gleichzeitig möglich, wie bei Spamhaus ZEN):

| Antwort | Bedeutung | Quelle (Tagesstand) |
|---|---|---|
| `127.0.0.2` | gelistet in der v64 Blocklist (allgemein, jede gelistete IP) | `ipv64_blocklist_v64.txt` |
| `127.0.0.3` | SSH-/Telnet-Brute-Force | `ipv64_blocklist_v64_ssh.txt` |
| `127.0.0.4` | Web-Angriffe (Login-Seiten, Exploits, Scans) | `ipv64_blocklist_v64_web.txt` |
| `127.0.0.5` | **Mail-Login-Brute-Force** (SMTP-AUTH, IMAP, POP3) | `ipv64_blocklist_v64_mail.txt` |
| `127.0.0.6` | RDP-Brute-Force | `ipv64_blocklist_v64_rdp.txt` |
| `127.0.0.7` | Port-Scanner, bloße Verbindungsversuche, Scanner-User-Agents | `ipv64_blocklist_v64_scanner.txt` |
| NXDOMAIN | nicht gelistet | – |

- **Forschungs-Scanner (research)** stehen **nicht** in der DNSBL (wie in der v64 Blocklist).
- TXT (TTL 300): `Listed by IPv64.net Honeypot64 (ssh,mail): https://ipv64.net/honeypot/ip.php?ip=1.2.3.4`
- **Testeinträge nach RFC 5782:** `2.0.0.127.bl.ipv64.net` → `127.0.0.2` (und IPv6 `::ffff:7f00:2`) antwortet immer,
  auch bei leerer Liste; `1.0.0.127.bl.ipv64.net` antwortet nie.
- IPv6: 32 umgekehrte Nibbles, z. B. `2001:db8:1:2:3:4:567:89ab` →
  `b.a.9.8.7.6.5.0.4.0.0.0.3.0.0.0.2.0.0.0.1.0.0.0.8.b.d.0.1.0.0.2.bl.ipv64.net`.
- Nur Einzeladressen; Netze (falls je eine Liste welche enthält) werden übergangen.

**Aktualität:** Tagesstand für alle (wie die freie v64 Blocklist, bis zu 24 h alt). Ausnahme: **Freigaben**
(`hp_allowlist`, geschützte Anträge) nimmt die DNSBL beim nächsten stündlichen Lauf sofort heraus – ein Mailserver soll
eine freigegebene IP nicht noch bis zum nächsten Stichtag abweisen. **Später (TODO im Code):** Live-Antworten für
eingetragene Mailserver-IPs aller Klassen außer Standard (Plan Abschnitt 8).

## Entscheidung: eigene Zone mit Delegation

`bl.ipv64.net` wird eine **eigene Zone** auf denselben Nameservern (ns1/ns2.ipv64.net), in `ipv64.net` nur per NS
delegiert – nicht als Einträge in der Zone `ipv64.net`:

- Die DNSBL hat schnell zehntausende Namen (2 RRsets je IP); jede Änderung erhöht die Seriennummer und löst einen
  Zonentransfer zum Slave aus – das trifft dann nur die kleine Zone, nicht `ipv64.net`.
- Eigener SOA mit kurzen Zeiten (negative TTL 300), unabhängig von `ipv64.net`.
- Im Fehlerfall kann die ganze Zone gelöscht/neu angelegt werden, ohne `ipv64.net` anzufassen.
- Ist `ipv64.net` per DNSSEC signiert, ist die Delegation ohne DS-Eintrag „unsigniert“ – das ist für eine DNSBL in
  Ordnung (Spamhaus & Co. sind auch unsigniert). Ohne die NS-Delegation würden validierende Resolver die Antworten
  verwerfen, deshalb ist sie Pflicht.

## Einrichtung (einmalig, Dennis)

### 1. Prüfen, dass der Name frei ist

```bash
dig +short ANY bl.ipv64.net @ns1.ipv64.net        # soll leer sein
```

In der Zone `ipv64.net` darf es unter `bl` nichts geben (kein A/CNAME `bl.ipv64.net`, keine DynDNS-Subdomain `bl`).

### 2. SQL einspielen (Hauptdatenbank ipv64)

`deploy/sql/honeypot_h4_dnsbl.sql` – mehrfach ausführbar (`IF NOT EXISTS`), ändert keine bestehende Tabelle.
Legt an: `hp_dnsbl`.

```bash
mysql ipv64 < honeypot_h4_dnsbl.sql
```

### 3. Datei hochladen

| Datei im Repo | Ziel im Webroot (`/var/www/clients/client1/web58/web/`) |
|---|---|
| `deploy/web/bots/honeypot_dnsbl.php` | `bots/honeypot_dnsbl.php` (neu) |

**Nicht hochladen:** `deploy/web/honeypot/tests/` (Stubs und Testskripte). Das Skript bindet `../dbconnect.php` ein
(dort `$pdo`, `zone_update()`, `zone_create()`) und liest den Tagesstand aus `../blocklists/`.

### 4. Zone anlegen und delegieren

**Variante A – mit dem Skript** (nutzt `zone_create()` und `zone_update()` aus `dbconnect.php`, genau wie beim
Anlegen eigener Domains: Master auf 195.201.223.103, Slave auf 157.90.241.20 mit Master 10.10.0.2):

```bash
cd /var/www/clients/client1/web58/web/bots
php honeypot_dnsbl.php --create-zone --dry      # zeigt die drei JSON-Anfragen, schreibt nichts
php honeypot_dnsbl.php --create-zone            # legt an
```

Das macht:

1. `zone_create` auf Master und Slave: Zone `bl.ipv64.net.`, `soa_edit_api INCREASE`, NS `ns1.ipv64.net.`,
   `ns2.ipv64.net.`, SOA (TTL 300) `ns1.ipv64.net. hostmaster.ipv64.net. 1 900 300 604800 300`
   (refresh 15 min, retry 5 min, expire 7 Tage, negative TTL 5 min).
2. `zone_update` auf `ipv64.net`: **nur** das NS-RRset `bl.ipv64.net.` → `ns1.ipv64.net.`, `ns2.ipv64.net.`
   (TTL 3600, REPLACE). Sonst wird an `ipv64.net` nichts geändert.

`zone_create()` meldet keinen Erfolg zurück – danach prüfen:

```bash
dig +short SOA bl.ipv64.net @ns1.ipv64.net
dig +short SOA bl.ipv64.net @ns2.ipv64.net      # Slave hat die Zone übernommen
dig +short NS bl.ipv64.net @ns1.ipv64.net        # Delegation
```

**Variante B – PowerDNS-Admin von Hand:** Zone `bl.ipv64.net` als Master auf ns1 (Slave auf ns2 wie bei den übrigen
Zonen), SOA wie oben, SOA-EDIT-API `INCREASE`, NS ns1/ns2.ipv64.net; in der Zone `ipv64.net` einen Eintrag
`bl` Typ NS mit `ns1.ipv64.net.` und `ns2.ipv64.net.`, TTL 3600.

Eintrags-TTL (300) setzt der Cron selbst. Zonentransfer zum Slave läuft wie bei allen anderen Zonen.

### 5. Erster Lauf

```bash
php honeypot_dnsbl.php --dry       # nur Zahlen: Quelle, Soll, neu/geändert/entfernt, Blöcke
php honeypot_dnsbl.php             # schreibt alles (beim ersten Lauf ist jeder Name neu)
```

Danach prüfen (auch von außen, über einen normalen Resolver):

```bash
dig +short 2.0.0.127.bl.ipv64.net          # 127.0.0.2 (Testeintrag)
dig +short TXT 2.0.0.127.bl.ipv64.net      # "Test entry (RFC 5782), IPv64.net Honeypot64 DNSBL"
dig 1.0.0.127.bl.ipv64.net | grep status   # NXDOMAIN
```

und eine IP aus `blocklists/ipv64_blocklist_v4_v64.txt` rückwärts abfragen.

### 6. Cron

Stündlich, nach dem Tagesstand (der entsteht beim ersten Generator-Lauf des UTC-Tages um 00:07); die übrigen Läufe
finden nichts oder holen fehlgeschlagene Blöcke nach:

```
50 * * * * php /var/www/clients/client1/web58/web/bots/honeypot_dnsbl.php >> /var/www/clients/client1/web58/private/honeypot_dnsbl.log 2>&1
```

Logzeilen je Lauf (Laufzeit und Anzahl):

```
2026-10-21 00:50:02 UTC bl.ipv64.net: Tagesstand 2026-10-21 00:07 UTC, Quelle 1203 IPs (Netze uebergangen 0, ungueltig 0, freigegeben 0), Soll 1203, Zone 1203
  neu 1, geaendert 1, entfernt 1, gleich 1203; Bloecke 1 (ok 1, Fehler 0), Namen geschrieben 3; Laufzeit 0.03 s
```

Exit-Code 1 bei Abbruch oder fehlgeschlagenen Blöcken (Zeile `FEHLER: …`).

## Wie der Abgleich arbeitet

- **Quelle:** Tagesstand-Dateien im Ordner `blocklists/` (Hauptliste + Teillisten). Datei jünger als 60 s → der
  Generator schreibt gerade, nächster Lauf. Tagesstand älter als 3 Tage → Warnung (Generator prüfen).
- **Zustand:** `hp_dnsbl` (eine Zeile je Name mit A-Records und TXT). Geschrieben werden nur neue, geänderte und
  entfallene Namen: `REPLACE` für A + TXT, `DELETE` für entfallene.
- **Blöcke:** höchstens 1000 RRsets je `zone_update`-Aufruf (500 Namen); A und TXT eines Namens immer im selben Block.
  Der Zustand wird erst nach Erfolg des Blocks (HTTP 204) geschrieben. Schlägt ein Block fehl, holt ihn der nächste
  Lauf nach; nach 3 Fehlern in Folge bricht der Lauf ab.
- **Schutz der Zone:** keine Änderung, wenn die Hauptliste fehlt/unlesbar ist, mehr als 1 % der Zeilen ungültig sind,
  die Quelle leer ist, die Zone aber Einträge hat, oder die Quelle (ab 200 Einträgen) mehr als 50 % kleiner ist als
  der letzte Stand. Absichtlich trotzdem: `--force`. Die Testeinträge bleiben in jedem Fall.
- **Nicht zweimal gleichzeitig** (Sperrdatei im Temp-Ordner).
- `--full` schreibt alle Soll-Namen neu (z. B. nach Neuanlage der Zone, wenn `hp_dnsbl` noch voll ist).
- Last: anfangs ein `PATCH` je 500 IPs, danach täglich wenige. Jeder `PATCH` erhöht die Seriennummer; beim ersten
  großen Lauf kann der Slave deshalb mehrere Zonentransfers hintereinander machen – unkritisch, die Zone ist klein.

## So nutzen (für die Doku/den Leitfaden)

> Die DNS-Sperrliste `bl.ipv64.net` enthält die Angreifer-IPs der v64 Blocklist (Honeypot64) im Tagesstand. Sie
> eignet sich als **zusätzliches Signal** – die IPs fallen durch Angriffe auf, nicht zwingend durch Spam. Empfehlung:
> zuerst **nur protokollieren bzw. als Punktwert** verwenden und erst nach einigen Tagen Beobachtung hart abweisen.

**Abfrage selbst testen**

```bash
dig +short 2.0.0.127.bl.ipv64.net                       # Testeintrag -> 127.0.0.2
ip=203.0.113.7; dig +short $(echo $ip | awk -F. '{print $4"."$3"."$2"."$1}').bl.ipv64.net
dig +short TXT 2.0.0.127.bl.ipv64.net                   # Grund und Link
```

### Postfix

Erst beobachten – `warn_if_reject` schreibt nur `reject_warning` ins Mail-Log:

```
smtpd_recipient_restrictions =
    permit_mynetworks,
    permit_sasl_authenticated,
    reject_unauth_destination,
    warn_if_reject reject_rbl_client bl.ipv64.net=127.0.0.[2..7]
```

Danach z. B. nur Mail-Login-Angreifer abweisen (`reject_rbl_client bl.ipv64.net=127.0.0.5`) oder mit postscreen als
Gewicht neben anderen Listen statt allein entscheiden:

```
postscreen_dnsbl_sites = zen.spamhaus.org*3, bl.ipv64.net=127.0.0.2*1, bl.ipv64.net=127.0.0.5*2
postscreen_dnsbl_threshold = 3
postscreen_dnsbl_action = enforce
```

Für die Einlieferung (Port 587/465) ist `127.0.0.5` besonders passend: diese IPs haben bei Honeypots Mail-Logins
durchprobiert.

### rspamd

`/etc/rspamd/local.d/rbl.conf`:

```
rbls {
  ipv64 {
    symbol = "RBL_IPV64";
    rbl = "bl.ipv64.net";
    ipv4 = true;
    ipv6 = true;
    from = true;          # verbindende IP
    received = false;
    returncodes {
      RBL_IPV64_ATTACKER = "127.0.0.2";
      RBL_IPV64_MAIL = "127.0.0.5";
    }
  }
}
```

`/etc/rspamd/local.d/rbl_group.conf` (Punktwerte vorsichtig, nach Beobachtung anpassen):

```
symbols = {
  "RBL_IPV64_ATTACKER" { weight = 1.0; description = "IPv64.net Honeypot64: Angreifer-IP"; }
  "RBL_IPV64_MAIL" { weight = 2.0; description = "IPv64.net Honeypot64: Mail-Login-Angriffe"; }
}
```

### SpamAssassin

`local.cf`:

```
header   __RCVD_IN_IPV64     eval:check_rbl('ipv64-lastexternal', 'bl.ipv64.net.')
tflags   __RCVD_IN_IPV64     net

header   RCVD_IN_IPV64       eval:check_rbl_sub('ipv64-lastexternal', '127.0.0.2')
describe RCVD_IN_IPV64       Absender-IP auf der IPv64.net Honeypot64 Sperrliste
tflags   RCVD_IN_IPV64       net
score    RCVD_IN_IPV64       1.0

header   RCVD_IN_IPV64_MAIL  eval:check_rbl_sub('ipv64-lastexternal', '127.0.0.5')
describe RCVD_IN_IPV64_MAIL  Absender-IP greift Mail-Logins an (IPv64.net Honeypot64)
tflags   RCVD_IN_IPV64_MAIL  net
score    RCVD_IN_IPV64_MAIL  1.5
```

### Limits und Fair Use (Entwurf, Dennis entscheidet)

- Abfragen bitte über einen **eigenen, cachenden Resolver** (unbound, Knot Resolver, der Resolver des Mailservers) –
  nicht über öffentliche Resolver wie 8.8.8.8, 1.1.1.1 oder 9.9.9.9. Viele Sperrlisten beantworten Abfragen über
  öffentliche Resolver nicht oder falsch; ipv64 behält sich vor, das ebenso zu tun.
- Die Nutzung ist frei (Tagesstand). Bei sehr vielen Abfragen behält sich ipv64 eine Drosselung vor; Limits über die
  Klassenwerte sind geplant (Plan Abschnitt 8, „DNS-Sperrliste zählt je abfragender IP bzw. je eingetragenem
  Mailserver“). Wer sehr viele Abfragen hat, lädt besser die Liste `ipv64_blocklist_v64.txt` täglich herunter.
- Ohne Gewähr; Fehlalarme über die IP-Auskunft melden (Freigabe-Antrag), Freigaben wirken in der DNSBL innerhalb einer
  Stunde.

## Tests

```bash
bash deploy/web/honeypot/tests/h4_dnsbl/run_agentbox.sh
```

Auf der Testbox, alles mit Präfix `hp4b-`, danach entfernt (das Image `powerdns/pdns-auth-49` bleibt im Cache):

1. **Logik** (`run_tests.php`, PHP 8.3, SQLite im Speicher, `zone_update` als Stub, der die RRset-Änderungen aufzeichnet
   und die Zone nachbildet): Namen IPv4/IPv6 mit den RFC-5782-Beispielen, Codes je Art, TXT, Quelle lesen (research
   nicht, nur Teilliste nicht, Netze übergangen), Differenz neu/geändert/entfernt, Blöcke (höchstens 1000 RRsets,
   A + TXT nie getrennt), Fehler und Wiederholung, Abbruch nach 3 Fehlern, Schutz bei leerer/fehlender/kaputter/stark
   geschrumpfter Quelle, `--force`, `--dry`, `--full`, Freigaben, Testeinträge, Einrichtungs-Anfragen. 84 Prüfungen.
2. **Echter PowerDNS** (`pdns_test.php`, powerdns/pdns-auth-49 mit gsqlite3, Zone als Native ohne NOTIFY,
   Test-Key zufällig je Lauf): 1203 IPs in 3 Blöcken, danach Abfragen per `sdig` (Testeintrag, TTL 300, NXDOMAIN für
   127.0.0.1 und research, Codes, TXT mit Link, IPv6), zweiter Lauf schreibt nur die Differenz, dritter nichts.
   23 Prüfungen.

## Offen

- Live-Antworten für eingetragene Mailserver (Klassen außer Standard) – eigene Zone oder Ansicht je abfragender IP
  (z. B. dnsdist vor PowerDNS), Eintragen der Mailserver-IPs im Account.
- Limits je abfragender IP (dnsdist `MaxQPSIPRule` o. ä.) und Statistik der Abfragen.
- Hinweis auf `bl.ipv64.net` auf der Listenseite/im Leitfaden und in der Datenschutzerklärung (andere Teile von H4).
