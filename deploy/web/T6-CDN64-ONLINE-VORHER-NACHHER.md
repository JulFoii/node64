# CDN64 online – Phase T6 einspielen (ipv64.net)

Statistik über CDN64, ausgefallenen Server aus dem DNS nehmen (G6). Getestet in der Testumgebung (64 Prüfungen).

## 1. SQL (Hauptdatenbank ipv64)

Die drei neuen Zeilen am Ende von `deploy/sql/cdn64_online.sql` (die ganze Datei geht auch, sie ist mehrfach
ausführbar):

```sql
ALTER TABLE `cdn64o_traffic` ADD COLUMN IF NOT EXISTS `requests` bigint(20) NOT NULL DEFAULT 0 AFTER `conns`;
ALTER TABLE `cdn64o_edges` ADD COLUMN IF NOT EXISTS `withdrawn` tinyint(1) NOT NULL DEFAULT 0 AFTER `disabled`;
ALTER TABLE `cdn64o_edges` ADD COLUMN IF NOT EXISTS `back_since` datetime DEFAULT NULL AFTER `withdrawn`;
```

## 2. Datei ersetzen

`deploy/web/api_v2_cdn64o.php` über die vorhandene Datei kopieren. `api_v2.php` bleibt unverändert.

## Was neu ist

- **Statistik:** Die Server melden Anfragen und Abweisungen je Name (`cdn64o_traffic.requests`/`rejected`);
  `GET /cdn64o/stats?days=30` liefert die Zahlen je Name und Tag, `traffic_month` der Hosts enthält sie.
- **G6:** Jeder Konfigurationsabruf eines Servers (alle 10 s) zählt als Lebenszeichen. Fehlt einer 45 s, während
  der andere ohne Pause da war, fragt ipv64 dessen `/health` (höchstens einmal je Minute); antwortet er auch dort
  nicht, verschwinden seine A/AAAA aus allen CDN64-Namen (`withdrawn = 1`, Ereignis `edge_down`). Ist er wieder
  30 s da, kommen sie zurück (`edge_back`). Fällt ipv64 selbst aus, wird niemand ausgetragen.
- PHP braucht dafür ausgehend HTTP (Port 80) zu den Servern (`file_get_contents` mit 3 s Zeitlimit).
