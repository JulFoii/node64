<?php
/**
 * IPv64.net – Admin-Bereich (admin.php): Nutzer suchen, Statistik, Klasse/Laufzeit, Sperren, Domains und Account
 * loeschen, Login als Nutzer. Nur fuer Admins (users.admin = 1, bei jedem Aufruf aus der Datenbank geprueft).
 *
 * Grundsaetze:
 * - Jede Aktion steht im Admin-Protokoll (Tabelle admin_audit, SQL im Upload) und neutral im Log des Nutzers
 *   (add_log, wie bei der Account-Verknuepfung sichtbar fuer ihn).
 * - Andere Admins lassen sich nicht sperren, loeschen oder uebernehmen.
 * - Login als Nutzer nutzt die Account-Verknuepfung (account_links) mit eigenem Status 9: Banner und
 *   "Zurueck in den eigenen Account" (header.php ?link_back=1) funktionieren wie beim Verknuepfen; der Eintrag wird
 *   danach weggeraeumt (adm_cleanup_links). Status 9 gilt nirgends als echte Verknuepfung (dort immer status = 1).
 * - Account loeschen = dieselbe Routine wie "eigenen Account loeschen" (account.php ?deleteaccount); Zahlungen bleiben.
 */

const ADM_LINK_STATUS = 9;     // account_links.status fuer "Admin angemeldet als"
const ADM_SEARCH_LIMIT = 50;

function adm_h($s): string { return htmlspecialchars((string)$s, ENT_QUOTES, 'UTF-8'); }

/** Abfrage mit Parametern; Fehler (z. B. fehlende Tabelle) -> null. */
function adm_q(PDO $pdo, string $sql, array $args = array()): ?PDOStatement {
	try {
		$st = $pdo->prepare($sql);
		$st->execute($args);
		return $st;
	} catch(Throwable $e) {
		error_log('admin: ' . $e->getMessage());
		return null;
	}
}

function adm_one(PDO $pdo, string $sql, array $args = array()): ?array {
	$st = adm_q($pdo, $sql, $args);
	$r = $st ? $st->fetch(PDO::FETCH_ASSOC) : false;
	return $r === false ? null : $r;
}

function adm_all(PDO $pdo, string $sql, array $args = array()): array {
	$st = adm_q($pdo, $sql, $args);
	return $st ? $st->fetchAll(PDO::FETCH_ASSOC) : array();
}

/** Anzahl; null = Tabelle gibt es (noch) nicht. $db: andere Datenbank auf demselben Server (Healthchecks 2.0). */
function adm_count(PDO $pdo, string $table, string $where = 'userid = :u', array $args = array(), string $db = ''): ?int {
	$t = ($db !== '' ? "`$db`." : '') . "`$table`";
	$st = adm_q($pdo, "SELECT COUNT(*) FROM $t WHERE $where", $args);
	return $st ? (int)$st->fetchColumn() : null;
}

/** Verbindung zur Datenbank von Healthchecks 2.0 (dbconnect_hc2.php, eigene Datenbank) oder null. */
function adm_hc2(): ?PDO {
	if(!function_exists('hc2_pdo') && is_file(__DIR__ . '/dbconnect_hc2.php')) { require_once __DIR__ . '/dbconnect_hc2.php'; }
	if(!function_exists('hc2_pdo')) { return null; }
	try { return hc2_pdo(); } catch(Throwable $e) { error_log('admin hc2: ' . $e->getMessage()); return null; }
}

function adm_hc2_db(): string { return defined('HC2_DB') ? HC2_DB : 'ipv64_hc'; }

/** Admin-Recht aus der Datenbank (nicht aus der Sitzung). */
function adm_is_admin(PDO $pdo, $uid): bool {
	if((int)$uid <= 0) { return false; }
	return (string)(adm_one($pdo, "SELECT admin FROM users WHERE id = :u", array('u' => (int)$uid))['admin'] ?? '0') === '1';
}

// ---------------------------------------------------------------- Protokoll

function adm_audit(PDO $pdo, int $admin, int $target, string $action, string $details = ''): void {
	adm_q($pdo, "INSERT INTO admin_audit (created_at, admin_id, target_id, action, details, ip) VALUES (UTC_TIMESTAMP(), :a, :t, :ac, :d, :ip)",
		array('a' => $admin, 't' => $target, 'ac' => mb_substr($action, 0, 50), 'd' => mb_substr($details, 0, 1000), 'ip' => mb_substr((string)($_SERVER['REMOTE_ADDR'] ?? ''), 0, 45)));
}

function adm_audit_list(PDO $pdo, int $target = 0, int $limit = 30): array {
	$where = $target > 0 ? 'WHERE a.target_id = :t' : '';
	$args = $target > 0 ? array('t' => $target) : array();
	return adm_all($pdo, "SELECT a.*, ua.email AS admin_email, ut.email AS target_email FROM admin_audit a
		LEFT JOIN users ua ON ua.id = a.admin_id LEFT JOIN users ut ON ut.id = a.target_id $where ORDER BY a.id DESC LIMIT " . max(1, min(200, $limit)), $args);
}

/** Eintrag im Log des Nutzers (wie das Portal, sichtbar unter Logs). */
function adm_userlog(PDO $pdo, int $uid, string $text): void {
	if(function_exists('add_log')) {
		try { add_log($pdo, $uid, "0", "Support", $text); } catch(Throwable $e) { error_log('admin add_log: ' . $e->getMessage()); }
	}
}

// ---------------------------------------------------------------- Suche

/** Suche nach ID, E-Mail (Teilstueck) oder Domain (Besitzer). */
function adm_search(PDO $pdo, string $q): array {
	$q = trim($q);
	if($q === '') { return array(); }
	$cols = "u.id, u.email, u.user_class, u.class_valid_until, u.account_status, u.admin, u.moderator, u.reg_date, u.last_login, c.name AS class_name";
	$from = "FROM users u LEFT JOIN user_class c ON c.id = u.user_class";
	if(ctype_digit($q)) {
		return adm_all($pdo, "SELECT $cols $from WHERE u.id = :id", array('id' => (int)$q));
	}
	$like = '%' . strtr($q, array('\\' => '\\\\', '%' => '\\%', '_' => '\\_')) . '%';
	$out = adm_all($pdo, "SELECT $cols $from WHERE u.email LIKE :q OR u.username LIKE :q2 ORDER BY u.id LIMIT " . ADM_SEARCH_LIMIT, array('q' => $like, 'q2' => $like));
	if(strpos($q, '@') === false && strpos($q, '.') !== false) { // Domain: Besitzer finden
		$name = strtolower(rtrim($q, '.'));
		$hits = adm_all($pdo, "SELECT DISTINCT userid FROM subdomains WHERE subdomainname = :n OR CONCAT(subdomainname, '.', maindomain) = :n2 OR subdomainname LIKE :l LIMIT " . ADM_SEARCH_LIMIT,
			array('n' => $name, 'n2' => $name, 'l' => $like));
		$have = array_column($out, 'id');
		foreach($hits as $h) {
			if(!in_array($h['userid'], $have)) {
				$r = adm_one($pdo, "SELECT $cols $from WHERE u.id = :id", array('id' => (int)$h['userid']));
				if($r) { $r['via_domain'] = true; $out[] = $r; }
			}
		}
	}
	return $out;
}

// ---------------------------------------------------------------- Nutzer und Statistik

function adm_user(PDO $pdo, int $uid): ?array {
	return adm_one($pdo, "SELECT u.*, c.name AS class_name FROM users u LEFT JOIN user_class c ON c.id = u.user_class WHERE u.id = :u", array('u' => $uid));
}

function adm_classes(PDO $pdo): array {
	return adm_all($pdo, "SELECT id, name FROM user_class ORDER BY id");
}

/** Zahlen zum Account; Tabellen, die es nicht gibt, fehlen in der Liste. */
function adm_stats(PDO $pdo, int $uid): array {
	$u = array('u' => $uid);
	$hc = adm_hc2();
	$db = adm_hc2_db();
	$rows = array(
		'Domains (DynDNS)' => adm_count($pdo, 'subdomains', 'userid = :u AND owndomain = 0', $u),
		'Domains (eigene)' => adm_count($pdo, 'subdomains', 'userid = :u AND owndomain != 0', $u),
		'DNS-Einträge' => adm_count($pdo, 'subdomain_records', 'userid = :u', $u),
		'Healthchecks (alt)' => adm_count($pdo, 'healthchecks', 'userid = :u', $u),
		'Healthchecks 2.0' => $hc ? adm_count($hc, 'hc2_checks', 'userid = :u AND deleted_at IS NULL', $u, $db) : null,
		'Node64-Nodes' => $hc ? adm_count($hc, 'hc2_nodes', 'userid = :u AND revoked_at IS NULL', $u, $db) : null,
		'Benachrichtigungskanäle' => $hc ? adm_count($hc, 'hc2_channels', 'userid = :u AND deleted_at IS NULL', $u, $db) : null,
		'Integrationen (alt)' => adm_count($pdo, 'integrations', 'userid = :u', $u),
		'Statusseiten' => adm_count($pdo, 'status_pages', 'userid = :u', $u),
		'DNS-Failover-Regeln' => adm_count($pdo, 'dns_failover_rules', 'userid = :u', $u),
		'CDN-Domains' => adm_count($pdo, 'cdn_domains', 'userid = :u', $u),
		'CDN64-Namen' => adm_count($pdo, 'cdn64o_hosts', 'userid = :u', $u),
		'Cloud Router' => adm_count($pdo, 'vpn_gateways', 'userid = :u', $u),
		'VPN-Peers' => adm_count($pdo, 'vpn_gw_wg_peers', 'userid = :u', $u),
		'DNS64-Clients' => adm_count($pdo, 'dns64_clients', 'userid = :u', $u),
		'Honeypot-Sensoren' => adm_count($pdo, 'hp_sensors', 'userid = :u', $u),
		'Eigene Blocklisten' => adm_count($pdo, 'blocklisten_user', 'userid = :u', $u),
		'API-Keys' => adm_count($pdo, 'api_keys', 'userid = :u', $u),
		'2FA-Schlüssel' => adm_count($pdo, '2fa_integrations', 'userid = :u', $u),
		'Verknüpfungen' => adm_count($pdo, 'account_links', '(owner_id = :u OR manager_id = :u2) AND status = 1', array('u' => $uid, 'u2' => $uid)),
		'Zahlungen' => adm_count($pdo, 'payments', 'userid = :u', $u),
	);
	return array_filter($rows, function($v) { return $v !== null; });
}

function adm_domains(PDO $pdo, int $uid): array {
	return adm_all($pdo, "SELECT s.id, s.subdomainname, s.maindomain, s.owndomain, s.reg_date, s.last_update, s.update_count, s.deactivated,
		(SELECT COUNT(*) FROM subdomain_records r WHERE r.subdomain_id = s.id) AS records FROM subdomains s WHERE s.userid = :u ORDER BY s.id", array('u' => $uid));
}

function adm_payments(PDO $pdo, int $uid): array {
	return adm_all($pdo, "SELECT id, payment_time, payment_info FROM payments WHERE userid = :u ORDER BY payment_time DESC LIMIT 5", array('u' => $uid));
}

function adm_logs(PDO $pdo, int $uid, int $limit = 20): array {
	return adm_all($pdo, "SELECT zeit, header, content FROM logging WHERE userid = :u ORDER BY id DESC LIMIT " . max(1, min(100, $limit)), array('u' => $uid));
}

// ---------------------------------------------------------------- Aktionen

/** Klasse, Laufzeit und Domainlimit setzen. */
function adm_set_class(PDO $pdo, int $uid, int $class, string $until, ?int $domainlimit): bool {
	if(adm_one($pdo, "SELECT id FROM user_class WHERE id = :c", array('c' => $class)) === null) { return false; }
	$t = strtotime($until);
	if($t === false) { return false; }
	$args = array('c' => $class, 'v' => date('Y-m-d H:i:s', $t), 'u' => $uid);
	$set = "user_class = :c, class_valid_until = :v";
	if($domainlimit !== null) { $set .= ", domainlimit = :d"; $args['d'] = max(0, min(100000, $domainlimit)); }
	return adm_q($pdo, "UPDATE users SET $set WHERE id = :u", $args) !== null;
}

/** Verlaengerung um Monate ab max(heute, bisheriges Ende). */
function adm_extend_until(?string $current, int $months): string {
	$base = max(time(), (int)strtotime((string)$current));
	return date('Y-m-d 23:59:59', strtotime('+' . $months . ' months', $base));
}

/** Status: 0 = nicht freigeschaltet, 1 = aktiv, 2 = gesperrt. Sperren meldet ab. */
function adm_set_status(PDO $pdo, int $uid, int $status): bool {
	if(!in_array($status, array(0, 1, 2), true)) { return false; }
	$set = "account_status = :s" . ($status === 2 ? ", sessionid = ''" : "");
	return adm_q($pdo, "UPDATE users SET $set WHERE id = :u", array('s' => $status, 'u' => $uid)) !== null;
}

/** DNS entschaerfen wie der Abuse-Bot (bots/dns_remove_ips.php): A/AAAA auf neutrale Adressen, DNS-Abgleich anstossen. */
function adm_neutralize_dns(PDO $pdo, int $uid): int {
	$n = 0;
	foreach(array('A' => '1.1.1.1', 'AAAA' => '2606:4700::6810:84e5') as $type => $ip) {
		$st = adm_q($pdo, "UPDATE subdomain_records SET content = :c, update_dns = 1 WHERE userid = :u AND type = :t", array('c' => $ip, 'u' => $uid, 't' => $type));
		$n += $st ? $st->rowCount() : 0;
	}
	return $n;
}

function adm_logout(PDO $pdo, int $uid): bool {
	return adm_q($pdo, "UPDATE users SET sessionid = '' WHERE id = :u", array('u' => $uid)) !== null;
}

function adm_reset_2fa(PDO $pdo, int $uid): int {
	$st = adm_q($pdo, "DELETE FROM 2fa_integrations WHERE userid = :u", array('u' => $uid));
	return $st ? $st->rowCount() : 0;
}

// ---------------------------------------------------------------- Traffic (Monat)

/**
 * Traffic des Monats: altes CDN (users.cdn_traffic_*, MB), neues CDN (cdn64o_traffic ab dem 1., Bytes), Cloud Router
 * (users.vpn_traffic_*, Bytes). Limits aus der Klasse (cdn_traffic fuer beide CDNs zusammen, vpn_traffic, je GB).
 */
function adm_traffic(PDO $pdo, array $user): array {
	$cls = adm_one($pdo, "SELECT cdn_traffic, vpn_traffic FROM user_class WHERE id = :c", array('c' => (int)$user['user_class'])) ?? array();
	$new = adm_one($pdo, "SELECT COALESCE(SUM(bytes_in + bytes_out), 0) b FROM cdn64o_traffic WHERE userid = :u AND day >= :d", array('u' => (int)$user['id'], 'd' => date('Y-m-01')));
	return array(
		'cdn_old_gb' => ((float)$user['cdn_traffic_input'] + (float)$user['cdn_traffic_output']) / 1024,
		'cdn64_gb' => $new === null ? null : (float)$new['b'] / 1073741824,
		'cdn_limit_gb' => (int)($cls['cdn_traffic'] ?? 0),
		'cdn64_blocked' => adm_count($pdo, 'cdn64o_hosts', "userid = :u AND status = 'blocked' AND blocked_reason = 'traffic'", array('u' => (int)$user['id'])),
		'vpn_gb' => ((float)$user['vpn_traffic_input'] + (float)$user['vpn_traffic_output']) / 1073741824,
		'vpn_limit_gb' => (int)($cls['vpn_traffic'] ?? 0),
		'vpn_limited' => (int)($user['vpn_limit_reached'] ?? 0) === 1,
	);
}

/**
 * Wegen Traffic gesperrte CDN64-Namen wieder aktiv, wenn altes und neues CDN zusammen unter dem Klassenlimit liegen
 * (wie api_v2_cdn64o.php beim naechsten Bericht der Server – hier sofort). Liefert die Anzahl.
 */
function adm_cdn64_unblock(PDO $pdo, int $uid): int {
	$u = adm_user($pdo, $uid);
	if($u === null) { return 0; }
	$t = adm_traffic($pdo, $u);
	if($t['cdn_limit_gb'] <= 0 || $t['cdn_old_gb'] + (float)$t['cdn64_gb'] >= $t['cdn_limit_gb']) { return 0; }
	$n = 0;
	foreach(adm_all($pdo, "SELECT id FROM cdn64o_hosts WHERE userid = :u AND status = 'blocked' AND blocked_reason = 'traffic'", array('u' => $uid)) as $h) {
		adm_q($pdo, "UPDATE cdn64o_hosts SET status = 'active', blocked_reason = '' WHERE id = :h", array('h' => $h['id']));
		adm_q($pdo, "INSERT INTO cdn64o_events (host_id, userid, kind, message) VALUES (:h, :u, 'unblocked', 'support: traffic reset')", array('h' => $h['id'], 'u' => $uid));
		$n++;
	}
	return $n;
}

/**
 * Altes CDN: Monatszaehler auf 0 wie bots/cdn_vpn_traffic_delete.php am 1. Beim Limit abgeschaltete Proxys/Portmapper
 * bleiben aus (vorheriger Zustand unbekannt), der Nutzer schaltet sie selbst wieder ein. Liefert entsperrte CDN64-Namen.
 */
function adm_reset_cdn_old(PDO $pdo, int $uid): int {
	adm_q($pdo, "UPDATE users SET cdn_traffic_input = 0, cdn_traffic_output = 0 WHERE id = :u", array('u' => $uid));
	return adm_cdn64_unblock($pdo, $uid);
}

/**
 * Neues CDN (CDN64): Bytes des laufenden Monats auf 0 (Verbindungen/Anfragen bleiben fuer die Statistik), danach
 * wegen Traffic gesperrte Namen freigeben. Liefert entsperrte Namen.
 */
function adm_reset_cdn64(PDO $pdo, int $uid): int {
	adm_q($pdo, "UPDATE cdn64o_traffic SET bytes_in = 0, bytes_out = 0 WHERE userid = :u AND day >= :d", array('u' => $uid, 'd' => date('Y-m-01')));
	return adm_cdn64_unblock($pdo, $uid);
}

/**
 * Cloud Router (VPN): wie der Monatswechsel – Zaehler und Limit-Merker auf 0, gedrosselte Gateways freigeben
 * (traffic_limit 2, vpn_bot setzt es um). Liefert die Anzahl der Gateways.
 */
function adm_reset_vpn(PDO $pdo, int $uid): int {
	adm_q($pdo, "UPDATE users SET vpn_traffic_input = 0, vpn_traffic_output = 0, vpn_limit_reached = 0 WHERE id = :u", array('u' => $uid));
	$st = adm_q($pdo, "UPDATE vpn_gateways SET traffic_limit = 2, actions = 'edit', status = 0 WHERE userid = :u AND traffic_limit = 1", array('u' => $uid));
	return $st ? $st->rowCount() : 0;
}

/** Eine Domain loeschen (wie in der Oberflaeche: Records, Zone, CDN-Markierung, Failover). */
function adm_delete_domain(PDO $pdo, int $uid, int $domainId): bool {
	if(adm_one($pdo, "SELECT id FROM subdomains WHERE id = :d AND userid = :u", array('d' => $domainId, 'u' => $uid)) === null) { return false; }
	del_domain($pdo, $uid, $domainId);
	return true;
}

/** Alle Domains des Nutzers loeschen (DNS komplett weg). */
function adm_delete_domains(PDO $pdo, int $uid): int {
	$n = 0;
	foreach(adm_all($pdo, "SELECT id FROM subdomains WHERE userid = :u", array('u' => $uid)) as $d) {
		del_domain($pdo, $uid, $d['id']);
		$n++;
	}
	// Reste, falls eine Domain nicht sauber durchlief (wie beim Loeschen des Accounts)
	adm_q($pdo, "DELETE FROM subdomain_records WHERE userid = :u", array('u' => $uid));
	adm_q($pdo, "DELETE FROM subdomains WHERE userid = :u", array('u' => $uid));
	return $n;
}

/**
 * Account mit allem loeschen – dieselbe Routine wie "eigenen Account loeschen" (account.php ?deleteaccount), nur ohne
 * Passwort des Nutzers und ohne dessen Sitzung zu beenden (die des Admins bleibt). Zahlungen bleiben (Buchhaltung).
 */
function adm_delete_account(PDO $pdo, int $uid): void {
	$userid = $uid;
	adm_delete_domains($pdo, $userid);
	$purge = function($sql, $args) use ($pdo) { try { $st2 = $pdo->prepare($sql); $st2->execute($args); return $st2; } catch(Exception $e) { return null; } };
	$u = array('userid' => $userid);
	//CDN: Domains dem Bot zum Abraeumen geben, Rest direkt
	$purge("UPDATE cdn_domains set dell = 1 WHERE userid = :userid", $u);
	foreach(array("cdn_block_ips","cdn_traffic") as $tab) { $purge("DELETE FROM $tab WHERE userid = :userid", $u); }
	//Cloud Router und DNS64: dem Bot zum Abraeumen geben
	$purge("UPDATE vpn_gateways set del_gw = 1,status = 0 WHERE userid = :userid", $u);
	$purge("UPDATE dns64_clients set actions = 1,del_client = 1 WHERE userid = :userid", $u);
	//Dateien: Offline-Page-Bilder und eigene Blocklisten (Pfade relativ zum Webroot wie in account.php)
	$st2 = $purge("SELECT picture FROM dns_offline_pages WHERE userid = :userid AND picture != ''", $u);
	foreach($st2 ? $st2->fetchAll() : array() as $pic) { if(is_file($pic["picture"])) { unlink($pic["picture"]); } }
	$st2 = $purge("SELECT listkey FROM blocklisten_user WHERE userid = :userid", $u);
	foreach($st2 ? $st2->fetchAll() : array() as $bl) { if($bl["listkey"] != "") { array_map('unlink', glob(__DIR__ . "/blocklists/user/ipv64_".$bl["listkey"]."*") ?: array()); } }
	//Node64 / CDN64
	$st2 = $purge("SELECT id, fqdn FROM cdn64o_hosts WHERE userid = :userid", $u);
	foreach($st2 ? $st2->fetchAll() : array() as $c64) {
		foreach(array("cdn64o_host_tunnels","cdn64o_records","cdn64o_targets","cdn64o_acl","cdn64o_mappings") as $tab) { $purge("DELETE FROM `$tab` WHERE host_id = :h", array('h' => $c64["id"])); }
		$purge("DELETE FROM cdn64o_certs WHERE fqdn = :f", array('f' => $c64["fqdn"]));
	}
	foreach(array("cdn64o_mappings","cdn64o_hosts","cdn64o_tunnels","cdn64o_traffic","cdn64o_events") as $tab) {
		$purge("DELETE FROM `$tab` WHERE userid = :userid", $u);
	}
	//Node64 / Healthchecks 2.0: eigene Datenbank (dbconnect_hc2.php); die hubs laden den Stand danach neu
	if($hc = adm_hc2()) {
		$db = adm_hc2_db();
		$hpurge = function($sql, $args) use ($hc) { try { $st3 = $hc->prepare($sql); $st3->execute($args); return $st3; } catch(Exception $e) { error_log('admin hc2 purge: ' . $e->getMessage()); return null; } };
		$st2 = $hpurge("SELECT token FROM `$db`.hc2_checks WHERE userid = :userid", $u);
		foreach($st2 ? $st2->fetchAll() : array() as $hcx) {
			foreach(array("hc2_check_states","hc2_measurements","hc2_hourly","hc2_daily","hc2_dirty_hours") as $tab) { $hpurge("DELETE FROM `$db`.`$tab` WHERE token = :t", array('t' => $hcx["token"])); }
		}
		$st2 = $hpurge("SELECT node_id FROM `$db`.hc2_nodes WHERE userid = :userid", $u);
		foreach($st2 ? $st2->fetchAll() : array() as $hn) {
			foreach(array("hc2_node_tokens","hc2_commands","hc2_send_orders") as $tab) { $hpurge("DELETE FROM `$db`.`$tab` WHERE node_id = :n", array('n' => $hn["node_id"])); }
		}
		foreach(array("hc2_checks","hc2_events","hc2_incidents","hc2_channels","hc2_deliveries","hc2_testruns","hc2_maintenance","hc2_settings",
			"hc2_usage_daily","hc2_api_sends","hc2_sms_counter","hc2_revisions","hc2_config_log","hc2_migration_log","hc2_compare_log",
			"hc2_link_codes","hc2_nodes") as $tab) {
			$hpurge("DELETE FROM `$db`.`$tab` WHERE userid = :userid", $u);
		}
	}
	//DNS64 (alt) und Honeypot64
	$st2 = $purge("SELECT client_id FROM dns64_clients WHERE userid = :userid AND dns64_server = '0'", $u);
	foreach($st2 ? $st2->fetchAll() : array() as $dc) { $purge("DELETE FROM dns64_queries WHERE client_id = :c", array('c' => $dc["client_id"])); }
	$purge("DELETE FROM dns64_clients WHERE userid = :userid AND dns64_server = '0'", $u);
	foreach(array("hp_sensors","hp_reports","hp_report_sources","hp_daily","hp_release_requests","hp_list_tokens","hp_list_token_files",
		"hp_sample_contrib","hp_watch","hp_watch_alerts","dns64_client_lists","dns64_ip_tracking") as $tab) {
		$purge("DELETE FROM `$tab` WHERE userid = :userid", $u);
	}
	//Alle Tabellen mit userid
	foreach(array("healthchecks","healthcheck_events","healthcheck_incidents","healthcheck_incident_events","integrations",
		"dns_failover_policies","dns_failover_rules","dns_failover_monitors","dns_offline_pages","status_pages",
		"blocklisten_user","blocker_nodes","blocker_reported_ips","blocker_reported_ips_history",
		"api_keys","2fa_integrations","url_shortener","product_request","30kbonus",
		"vpn_user_traffic","vpn_gw_wg_peers_connections","logging") as $tab) {
		$purge("DELETE FROM `$tab` WHERE userid = :userid", $u);
	}
	$purge("DELETE FROM account_links WHERE owner_id = :uid OR manager_id = :uid2", array('uid' => $userid, 'uid2' => $userid));
	$purge("DELETE FROM users WHERE id = :userid", $u);
}

// ---------------------------------------------------------------- Login als Nutzer

/**
 * Admin meldet sich als Nutzer an: wie die Account-Verknuepfung (account.php ?link_login), mit eigenem Eintrag
 * (status 9). Die Sitzung des Admins gehoert danach dem Nutzer; eine Sitzung des Nutzers selbst endet dabei
 * (eine Sitzung je Account). Zurueck ueber header.php ?link_back=1 (Banner auf der Account-Seite).
 */
function adm_login_as(PDO $pdo, int $admin, int $uid, string $session): bool {
	if($session === '' || $admin === $uid) { return false; }
	adm_cleanup_links($pdo);
	$ok = adm_q($pdo, "INSERT INTO account_links (owner_id, manager_id, status, created, last_used, last_session) VALUES (:o, :m, :s, NOW(), NOW(), :ss)",
		array('o' => $uid, 'm' => $admin, 's' => ADM_LINK_STATUS, 'ss' => $session)) !== null;
	if(!$ok) { return false; }
	adm_q($pdo, "UPDATE users SET sessionid = '' WHERE id = :id", array('id' => $admin));
	adm_q($pdo, "UPDATE users SET sessionid = :ss WHERE id = :id", array('ss' => $session, 'id' => $uid));
	return true;
}

/** Abgelaufene Admin-Anmeldungen wegraeumen (zurueck gewechselt oder aelter als einen Tag). */
function adm_cleanup_links(PDO $pdo): void {
	adm_q($pdo, "DELETE FROM account_links WHERE status = :s AND (last_session = '' OR last_used < NOW() - INTERVAL 1 DAY)", array('s' => ADM_LINK_STATUS));
}
