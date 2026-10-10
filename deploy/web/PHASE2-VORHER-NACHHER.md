# Phase 2 – Webseite: Versand-Brücke und Schlüssel

Der hub läuft auf beiden Servern und prüft Online-Checks. Für Benachrichtigungen über **ipv64-Mail, SMS und die App** braucht er die vorhandene Infrastruktur des Web-Servers (SMTP, internes SMS-Gateway, Firebase). Dafür gibt es eine kleine Brücke.

## 1. `hc2_send.php` in den Webroot

Datei `hc2_send.php` neben `health.php` ablegen. Sie nimmt nur signierte POST-Aufrufe des hub an (HMAC-SHA256, Zeitstempel ≤ 5 min) und ruft `send_mail()`, `send_sms()`, `send_firebase()` aus `dbconnect.php` auf. Für Besucher liefert sie nur `{"ok":false,"error":"method"}`.

## 2. Geheimnis der Brücke

Das Geheimnis liegt auf beiden hubs in `/etc/ipv64-hub/bridge.secret`. Es muss **identisch** nach

```
/var/www/clients/client1/web58/private/hc2_bridge.secret   (chmod 640, eine Zeile)
```

Ich kann es dir nicht in den Chat schreiben; hol es dir von hc-srv01: `cat /etc/ipv64-hub/bridge.secret` – oder sag Bescheid, dann lege ich es auf hc-srv01 unter `/root/hc2_bridge.secret` ab.

## 3. Schlüssel für Kanal-Geheimnisse (aus Phase 1)

`hc2_secret.key` (32 Rohbytes) muss auf Web-Server **und** beiden hubs gleich sein, sonst kann der hub Telegram-Tokens usw. nicht lesen, die das Portal verschlüsselt hat:

- Web-Server: `/var/www/clients/client1/web58/private/hc2_secret.key` (hast du in Phase 1 angelegt)
- hubs: `/var/lib/ipv64-hub/secret.key`

Lege die Datei auf hc-srv01 unter `/root/hc2_secret.key` ab (z. B. per `scp`), ich verteile sie dann auf beide hubs mit den richtigen Rechten. Solange sie fehlt, loggt der hub beim Start eine Warnung und Kanäle mit Geheimnissen schlagen beim Senden fehl – Checks laufen trotzdem.

## Prüfen

Nach Schritt 1+2 kann ich vom hub aus eine Testmail an die Adresse des Testaccounts schicken (`ipv64_mail`-Kanal) und eine Test-SMS, wenn du eine Nummer für den Testaccount hinterlegst.

## SMS-Limit (Rückfrage)

Heute zählt `users.sms_count` gegen `user_class.sms_limit` (das Feld wird von `send_sms()` hochgezählt). Der hub zählt zusätzlich **pro Tag** in `hc2_sms_counter` gegen dasselbe Limit und verweigert darüber. Wenn das Limit bei dir pro Monat gemeint ist, sag Bescheid – dann stelle ich den Zähler um.
