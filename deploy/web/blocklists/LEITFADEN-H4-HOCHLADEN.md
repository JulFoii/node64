# Honeypot64 H4: Leitfaden – Firmen-Firewalls, Live-Token, MikroTik-Container

Ergänzt den Integrationsleitfaden `v64_blocklist_integration_guide.php` (EN, DE über `?lang=de`) um die v64 Blocklist,
den Live-Abruf mit Listen-Token und Firmen-Firewalls. Die Anleitung für Honeypot64 als Container auf MikroTik
RouterOS steht in `docs/HONEYPOT64.md` (Repo-Doku, nicht hochladen).

Voraussetzung: H3 ist eingespielt (`honeypot/token.php`, `blocklists/live.php` mit Rewrite-Regel,
`honeypot/ip.php`), siehe `deploy/web/H3-HONEYPOT-VORHER-NACHHER.md` und `H3-FREIGABE-VORHER-NACHHER.md`. Sonst
zeigen die neuen Links auf `/honeypot/token.php` und `/honeypot/ip.php` ins Leere.

## Was sich im Leitfaden ändert

| Stelle | Vorher | Nachher |
|---|---|---|
| 1. Liste wählen, Tabelle | endet mit `cloudflare`, `aws`, `gcp` | neuer Block „v64 Blocklist (Honeypot64), nicht in `all`“: `v64`, Teillisten `v64_ssh`/`_web`/`_mail`/`_rdp`/`_scanner`, `v64_research` |
| 1. Liste wählen, unten | – | Absatz „Live-Stand der v64 Blocklist (Listen-Token)“ (Anker `#live`): Adresse `https://ipv64.net/blocklists/live/<token>/<datei>`, Token im Pfad (keine Kopfzeile), geheim halten, Abruf alle 30 min oder seltener, 5 min je Datei/429, 60 Abrufe je 5 min, ohne Berechtigung Tagesstand, unbekanntes Token 404 |
| 4. pfSense | – | Satz: URL-Tabellen werden einmal täglich geprüft, Live bringt dort nichts |
| 6. (neu) | – | „Firmen-Firewalls: Palo Alto, FortiGate, Sophos“ (Anker `#enterprise`), Kennzeichnung „nicht live getestet“ |
| 6.–10. | MikroTik 6, nginx 7, CrowdSec 8, Node64 9, Quellen 10 | um eins verschoben: 7 bis 11 |
| MikroTik | – | Satz: Live-URL `…/live/<token>/v64_mikrotik_<v4/v6>_v64.rsc`, Liste `IPv64-v64`, `interval=30m` |
| Node64 | – | Satz: mit hinterlegtem Listen-Token lädt PROXY64 die v64-Listen live |
| Quellen | – | Eintrag Honeypot64 (CC BY 4.0); Freigabe für v64-Listen über die IP-Auskunft |

## Getestet / nicht getestet

- `php -l` (PHP 8.3, Wegwerf-Container auf der Testbox): keine Syntaxfehler. Seite mit leerem `header.php`/`footer.php`
  in EN und DE ausgegeben: keine PHP-Warnungen, HTML-Struktur in Ordnung, Abschnitte 1–11 in der richtigen Reihenfolge.
- **Nicht live getestet:** Palo Alto, FortiGate, Sophos und der MikroTik-Container. Menüpfade und Befehle stammen aus
  der Herstellerdoku (Quellen unten).
- **Sophos:** Laut Doku nehmen Third-party threat feeds nur einzelne IPv4-Adressen, keine Netze. Der Generator
  schreibt jede Adresse als Netz (`1.2.3.4/32`). Ob Sophos `/32` annimmt, ist offen; im Leitfaden steht das so.
  Falls nicht: eigene Datei ohne Präfix für Sophos (Änderung im Generator, nicht Teil dieser Phase).
- Die Linux-Skripte (`blocklists/tools/*.sh`) haben die Adresse fest eingebaut und laden immer den Tagesstand. Für
  Live müsste `BASE` überschreibbar sein (nicht Teil dieser Phase).

## Hochladen

| Datei im Repo | Ziel im Webroot |
|---|---|
| `deploy/web/blocklists/v64_blocklist_integration_guide.php` | `/v64_blocklist_integration_guide.php` (ersetzt) |

Sonst nichts. `docs/HONEYPOT64.md` bleibt im Repo; die Doku auf node64.de zieht die Webseiten-Sitzung nach.

### Optional: Zahl der Integrationen

Datei `v64_secure.php` (falls dort nach dem letzten Leitfaden schon 9 steht):

VORHER

```php
						<p class="card-text h2">9</p>
```

NACHHER (dazu Palo Alto, FortiGate, Sophos)

```php
						<p class="card-text h2">12</p>
```

## Prüfen

- `https://ipv64.net/v64_blocklist_integration_guide` und `…?lang=de`: Tabelle mit dem v64-Block, Absatz „Live-Stand“,
  Abschnitt 6 „Firmen-Firewalls“, Nummern bis 11.
- Links `#live`, `/honeypot/token.php`, `/honeypot/ip.php`, `/honeypot/` öffnen.

## Quellen (Herstellerdoku)

- Palo Alto: <https://docs.paloaltonetworks.com/pan-os/11-1/pan-os-admin/policy/use-an-external-dynamic-list-in-policy/configure-the-firewall-to-access-an-external-dynamic-list>,
  <https://docs.paloaltonetworks.com/pan-os/11-1/pan-os-admin/policy/use-an-external-dynamic-list-in-policy/external-dynamic-list>,
  <https://docs.paloaltonetworks.com/pan-os/11-1/pan-os-admin/policy/use-an-external-dynamic-list-in-policy/enforce-policy-on-an-external-dynamic-list>
- FortiGate: <https://docs.fortinet.com/document/fortigate/7.6.4/administration-guide/379433/configuring-an-external-feed>,
  <https://docs.fortinet.com/document/fortigate/7.6.4/administration-guide/891236/ip-address-threat-feed>
- Sophos: <https://docs.sophos.com/nsg/sophos-firewall/21.5/Help/en-us/webhelp/onlinehelp/AdministratorHelp/ActiveThreatResponse/ConfigureFeeds/ThirdPartyThreatFeeds/ConfigureThirdPartyThreatFeeds/index.html>,
  <https://docs.sophos.com/nsg/sophos-firewall/22.0/Help/en-us/webhelp/onlinehelp/AdministratorHelp/ActiveThreatResponse/Requirements/Licenses/index.html>
- pfSense: <https://docs.netgate.com/pfsense/en/latest/firewall/aliases-types.html>
- OPNsense: <https://docs.opnsense.org/manual/aliases.html>
- MikroTik: <https://manual.mikrotik.com/docs/containers/>, <https://manual.mikrotik.com/docs/cli-reference/container/>,
  Changelogs 7.20 und 7.21 (<https://forum.mikrotik.com/t/v7-20-stable-is-released/265196>,
  <https://forum.mikrotik.com/t/v7-21-stable-is-released/267773>)
