# Netzwerkuebersicht

Die Netzwerkuebersicht ist unter **Healthchecks → Netzwerkübersicht** erreichbar. Sie ist eine geschuetzte,
schreibgeschuetzte Live-Ansicht und verwendet dieselbe Anmeldung wie Healthchecks. Programmgesteuert steht dieselbe
Momentaufnahme unter `GET /api/healthchecks/network-map` zur Verfuegung.

## Datenquellen und Grenzen

Die Ansicht kombiniert ausschliesslich Daten, die Node64 belastbar kennt:

- die eigene Node64-Instanz und gekoppelte Nodes,
- konfigurierte Healthchecks, deren Laufzeitstatus, Abhaengigkeiten und letzte Statusereignisse,
- Zielhosts aus Check-Konfigurationen (nicht als automatisch entdeckte Geraete),
- eingerichtete Proxmox-VE-Systeme mitsamt der letzten abgefragten Nodes, VMs und LXC-Containern,
- eingerichtete Docker-Hosts mitsamt den zuletzt abgefragten Containern und zugeordneten Docker-Checks.

Node64 fuehrt fuer diese Funktion keinen Port-, ARP-, SNMP- oder Broadcast-Scan aus. Solche Ergebnisse waeren ohne
einen ausgerollten Agenten oder explizite Zugangsdaten unvollstaendig und duerfen nicht als Topologie ausgegeben
werden. Unbekannte oder veraltete Daten erscheinen daher als `unknown` beziehungsweise `unchecked`; voruebergehend
nicht erreichbare Datenquellen werden in der Oberflaeche angezeigt.

## Betrieb

Die Browseransicht ruft die Momentaufnahme alle 15 Sekunden ab (bei einem ausgeblendeten Tab gedrosselt). Sie startet
keine neuen Abfragen: Healthchecks, Proxmox und Docker behalten ihre eigenen konfigurierten Intervalle. Dadurch bleibt
die Karte auch bei vielen Checks leichtgewichtig. Suche, Filter, Zoom, Verschieben und automatische Anordnung arbeiten
vollstaendig lokal im Browser; es werden keine externen JavaScript- oder Grafikbibliotheken geladen.

Fuer Docker-Container und Proxmox-Ressourcen muss die vorhandene Docker- beziehungsweise Proxmox-Ueberwachung
eingerichtet und erfolgreich abgefragt worden sein. Ohne diese Voraussetzungen zeigt die Karte keine geratenen
Container, IP-Adressen oder Verbindungen an.
