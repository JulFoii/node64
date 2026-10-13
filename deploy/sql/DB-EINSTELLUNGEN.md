# MariaDB-Einstellungen für Healthchecks 2.0 (Datenbankserver 10.100.0.110)

Grund: Lasttest mit 10.000 Accounts und 100.000 Checks (Okt. 2026). Dauerhaft etwa 1.700 Messpunkte und
1.700 Zustände pro Sekunde, gebündelt geschrieben. Zwei Werte sind dafür zu klein eingestellt:

| Einstellung | jetzt | neu | Wirkung |
|---|---|---|---|
| `innodb_log_file_size` | 96 MB | 1 GB | Redo-Log: bei 96 MB muss InnoDB unter Schreiblast sehr oft Daten auf die Platte zwingen (Stocken). |
| `innodb_io_capacity` | 200 | 1000 | 200 ist der Wert für drehende Festplatten; SSD/NVMe schafft weit mehr. |
| `innodb_io_capacity_max` | 2000 | 4000 | Obergrenze beim Nachholen. |

Alle übrigen Werte bleiben (Buffer Pool 24 GB, `innodb_flush_log_at_trx_commit = 1`).

## 1. Prüfen: SSD?

```bash
lsblk -d -o NAME,ROTA,SIZE
```
`ROTA 0` = SSD/NVMe: Werte wie oben. `ROTA 1` (Festplatte): `innodb_io_capacity` bei 200 lassen,
nur das Redo-Log vergrößern.

Freier Platz im Datenverzeichnis (`/var/lib/mysql`): mindestens 2 GB.

## 2. io_capacity sofort (ohne Neustart)

Als root in MariaDB:
```sql
SET GLOBAL innodb_io_capacity = 1000;
SET GLOBAL innodb_io_capacity_max = 4000;
```

## 3. Dauerhaft eintragen

Datei `/etc/mysql/mariadb.conf.d/90-ipv64-hc2.cnf` anlegen:
```ini
[mysqld]
innodb_log_file_size   = 1G
innodb_io_capacity     = 1000
innodb_io_capacity_max = 4000
```
(Falls dieselben Schlüssel schon in einer anderen Datei unter `/etc/mysql/` stehen, dort ändern statt doppelt
setzen: `grep -rn "innodb_log_file_size\|innodb_io_capacity" /etc/mysql/`.)

## 4. Neustart (nur für die Log-Größe nötig)

In einer ruhigen Zeit, die Webseite ist dabei kurz nicht erreichbar:
```bash
systemctl restart mariadb
```
MariaDB 10.5 legt das Redo-Log in der neuen Größe nach dem sauberen Herunterfahren selbst an. Die Hubs
warten den Neustart ab, die Nodes puffern ihre Messpunkte und liefern sie nach.

## 5. Kontrolle

```sql
SHOW VARIABLES WHERE Variable_name IN ('innodb_log_file_size','innodb_io_capacity','innodb_io_capacity_max');
```
Erwartet: 1073741824, 1000, 4000. Im Fehlerlog (`journalctl -u mariadb`) keine InnoDB-Fehler.
