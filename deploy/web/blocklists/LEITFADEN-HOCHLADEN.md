# Blocklisten: neuer Integrationsleitfaden

Der Leitfaden `v64_blocklist_integration_guide.php` ist neu geschrieben: Englisch, Deutsch über `?lang=de`, zehn
Abschnitte (Liste wählen, nftables, iptables+ipset, pfSense, OPNsense, MikroTik, nginx, CrowdSec, Node64, Quellen).

Getestet mit den echten Listen auf der Testbox, jeweils in einem abgeschotteten Container:

- nftables-Skript: Laden von IPv4 und IPv6, zweiter Lauf tauscht sauber aus.
- ipset-Skript: zweiter Lauf ohne doppelte Regeln, DOCKER-USER wird mitgenommen.
- nginx: `geo`-Datei mit 23.091 Einträgen, `nginx -t` ok.
- CrowdSec 1.6.4: 4.621 Einträge importiert.

pfSense, OPNsense und MikroTik sind nach den Menüs der aktuellen Versionen beschrieben, aber nicht live getestet.

## 1. Dateien hochladen

| Datei im Repo | Ziel auf ipv64.net |
|---|---|
| `deploy/web/blocklists/v64_blocklist_integration_guide.php` | `/v64_blocklist_integration_guide.php` (ersetzt die alte Seite) |
| `deploy/web/blocklists/tools/ipv64-blocklist-nft.sh` | `/blocklists/tools/ipv64-blocklist-nft.sh` (neuer Ordner `tools`) |
| `deploy/web/blocklists/tools/ipv64-blocklist-ipset.sh` | `/blocklists/tools/ipv64-blocklist-ipset.sh` |

Die Seite liest die Skripte aus `blocklists/tools/` und zeigt sie an. Seite und Download sind also immer gleich.

## 2. Generator: eigener Listenname je MikroTik-Datei

**Erledigt in der fertigen Datei** `site/bots/blocklist/create_blocklists_v2.php` (siehe FEHLER-HOCHLADEN.md). Der Abschnitt bleibt zur Erklärung stehen.

Bisher nutzen alle `.rsc`-Dateien den Listennamen `IPv64-Blocklist`. Wer zwei Listen importiert, löscht mit der
zweiten die Einträge der ersten. Der Leitfaden geht von `IPv64-<id>` aus (z. B. `IPv64-firehole_l1`).

Datei `bots/blocklist/create_blocklists_v2.php`

### Vorher

```php
	write_mikrotik("$OUT/v64_mikrotik_v4_$f.rsc", $v4, 4);
	write_mikrotik("$OUT/v64_mikrotik_v6_$f.rsc", $v6, 6);
```

### Nachher

```php
	write_mikrotik("$OUT/v64_mikrotik_v4_$f.rsc", $v4, 4, "IPv64-$f");
	write_mikrotik("$OUT/v64_mikrotik_v6_$f.rsc", $v6, 6, "IPv64-$f");
```

### Vorher

```php
write_mikrotik("$OUT/v64_mikrotik_v4_all.rsc", $v4, 4);
write_mikrotik("$OUT/v64_mikrotik_v6_all.rsc", $v6, 6);
```

### Nachher

```php
write_mikrotik("$OUT/v64_mikrotik_v4_all.rsc", $v4, 4, "IPv64-all");
write_mikrotik("$OUT/v64_mikrotik_v6_all.rsc", $v6, 6, "IPv64-all");
```

Wer schon die alten Dateien importiert hat, behält Einträge unter `IPv64-Blocklist`. Aufräumen auf dem Router:

```
/ip firewall address-list remove [find list=IPv64-Blocklist]
/ipv6 firewall address-list remove [find list=IPv64-Blocklist]
```

## 3. Zahl der Integrationen

Datei `v64_secure.php`

### Vorher

```php
						<p class="card-text h2">4</p>
```

### Nachher

```php
						<p class="card-text h2">9</p>
```

## Prüfen

- `https://ipv64.net/v64_blocklist_integration_guide` und `…?lang=de` laden, die Skripte unter „Show the script“ aufklappen.
- `curl -fsS https://ipv64.net/blocklists/tools/ipv64-blocklist-nft.sh | head -3` liefert den Kopf des Skripts.
- Nach dem nächsten Lauf des Generators: `curl -fsS https://ipv64.net/blocklists/v64_mikrotik_v4_firehole_l1.rsc | sed -n 3p`
  zeigt `remove [find list=IPv64-firehole_l1 comment="IPv64 Blocklist"]`.
