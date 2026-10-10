-- Hybrid-Vorbereitung: Messstellen und Bewertungsregel je Check.
-- policy: all | any | majority  (down nur wenn alle / eine / Mehrheit der Messstellen down)
-- locations: Online-Standorte bei execution online/both, kommagetrennt (z. B. nbg,fsn), leer = Vorgabe des Servers
-- notify_degraded: auch bei "teilweise gestoert" benachrichtigen
ALTER TABLE hc_checks ADD COLUMN policy TEXT NOT NULL DEFAULT 'all';
ALTER TABLE hc_checks ADD COLUMN locations TEXT NOT NULL DEFAULT '';
ALTER TABLE hc_checks ADD COLUMN notify_degraded INTEGER NOT NULL DEFAULT 0;
