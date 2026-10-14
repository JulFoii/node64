-- 2026-10-14: Tageskontingent der Online-Checks (healthcheck_update_limit der Account-Klasse)
-- Je Account und Tag (Europe/Berlin) die Online-Messungen je Standort plus Pushes an die Online-Adresse.
-- Der hub schreibt gebuendelt alle 30 s und loescht Zeilen aelter als 35 Tage.
CREATE TABLE IF NOT EXISTS `hc2_usage_daily` (
  `userid` INT NOT NULL,
  `day`    DATE NOT NULL,
  `checks` INT UNSIGNED NOT NULL DEFAULT 0,
  PRIMARY KEY (`userid`,`day`), KEY `day` (`day`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;
