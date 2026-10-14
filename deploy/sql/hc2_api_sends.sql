-- 2026-10-14: Versand ueber ipv64-Kanaele direkt ueber die API v2 (POST /hc2/channels/{id}/send):
-- Protokoll fuer Doppelte (event_id, 24 h), Tagesobergrenze je Account und Fehlersuche; Zeilen nach 35 Tagen geloescht.
CREATE TABLE IF NOT EXISTS `hc2_api_sends` (
  `id`         BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
  `userid`     INT NOT NULL,
  `channel_id` INT NOT NULL,
  `event_id`   VARCHAR(100) NULL,
  `kind`       VARCHAR(40) NOT NULL DEFAULT '',
  `source`     VARCHAR(60) NOT NULL DEFAULT '',
  `sent_at`    DATETIME(3) NOT NULL,
  `ok`         TINYINT NOT NULL DEFAULT 1,
  `error`      VARCHAR(255) NOT NULL DEFAULT '',
  PRIMARY KEY (`id`), KEY `user_day` (`userid`,`sent_at`), KEY `dedup` (`userid`,`channel_id`,`event_id`), KEY `sent_at` (`sent_at`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;
