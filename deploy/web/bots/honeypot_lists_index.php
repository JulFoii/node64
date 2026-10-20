<?php
/**
 * Honeypot64 (H4): Eintraege der Text-Listen (Passwoerter, Benutzernamen, User-Agents, Pfade) fuer blocklists/index.json.
 * Nur Konstanten und eine Funktion, keine Ausgabe, keine Datenbank: liest nur die Dateien unter blocklists/.
 * Eingebunden (require_once) von bots/honeypot_lists.php (schreibt die Listen), bots/blocklist/create_blocklists_v2.php
 * (voller Lauf baut index.json neu) und honeypot/hp_stats_lib.php (Groesse der Listen).
 *
 * Die Eintraege stehen in index.json unter "data" (nicht unter "lists"): Werkzeuge wie Node64/PROXY64 nehmen jeden
 * Eintrag in "lists" mit files.all als IP-Liste. Kategorie honeypot-data, Lizenz wie die v64 Blocklist.
 */

const HPL_LICENSE = 'CC BY 4.0 (IPv64.net Honeypot64), provided as is without warranty';
const HPL_SOURCE  = 'https://ipv64.net/honeypot/stats.php';
// id => [Name, Beschreibung, Hauptdatei, weitere Dateien (Schluessel => Datei)]
const HPL_DATA_LISTS = array(
	'honeypot_passwords' => array('Attacker passwords (Honeypot64)',
		'Most used passwords of attackers on Honeypot64 sensors (30 days, reported by several independent accounts), one per line, most used first; SHA-1 variant (uppercase, sorted) for tools',
		'ipv64_passwords.txt', array('sha1' => 'ipv64_passwords_sha1.txt')),
	'honeypot_usernames' => array('Attacker usernames (Honeypot64)',
		'Most used usernames of attackers on Honeypot64 sensors (30 days, several independent accounts), one per line, most used first',
		'ipv64_usernames.txt', array()),
	'honeypot_bad_useragents' => array('Bad user agents (Honeypot64)',
		'User agents of attack tools and scanners seen by Honeypot64 sensors (exact strings, browser-like agents left out); nginx map ($ipv64_bad_ua, exact match)',
		'ipv64_bad_useragents.txt', array('nginx_map' => 'ipv64_bad_useragents.nginx.map')),
	'honeypot_attack_paths' => array('Attack paths (Honeypot64)',
		'Web paths requested by attackers on Honeypot64 sensors (exploits, scans); nginx snippet with exact-match regex locations (return 403) for server blocks that do not serve these paths',
		'ipv64_attack_paths.txt', array('nginx_location' => 'ipv64_attack_paths.nginx.conf')),
);

/** Eintraege fuer index.json["data"] aus den vorhandenen Dateien in $dir (fehlende Listen fehlen auch hier). */
function hpl_index_entries(string $dir): array {
	$out = array();
	foreach(HPL_DATA_LISTS as $id => [$name, $desc, $main, $more]) {
		$p = "$dir/$main";
		if(!is_file($p)) { continue; }
		$files = array('txt' => $main);
		foreach($more as $k => $f) { if(is_file("$dir/$f")) { $files[$k] = $f; } }
		$out[] = array('id' => $id, 'name' => $name, 'category' => 'honeypot-data', 'in_all' => false, 'description' => $desc,
			'source' => HPL_SOURCE, 'license' => HPL_LICENSE, 'count' => count(file($p, FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES)),
			'updated' => date('c', filemtime($p)), 'files' => $files);
	}
	return $out;
}
