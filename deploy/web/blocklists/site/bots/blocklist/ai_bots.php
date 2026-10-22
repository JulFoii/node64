<?php
/**
 * KI-Bots: zwei Listen unter blocklists/, eingebunden von create_blocklists_v2.php (voller Lauf, kein eigener Cron).
 *
 *   ai_bots        IP-Netze aus den offiziellen JSON-Dateien der Betreiber (IPv4 + IPv6), index.json "lists", Kategorie ai
 *                  ipv64_blocklist_ai_bots.txt (+ _v4_, _v6_, MikroTik), ipv64_blocklist_ai_bots_sources.txt (Netz # Quellen)
 *   ai_useragents  User-Agent-Kennungen aus ai.robots.txt (Spiegel, damit niemand von GitHub abhaengt), index.json "data"
 *                  ipv64_ai_useragents.txt (eine Kennung je Zeile), ipv64_ai_useragents.json (mit Betreiber, Zweck,
 *                  Beschreibung, user = Abruf auf Anfrage eines Nutzers), ipv64_ai_robots.txt (robots.txt-Block)
 *
 * Quellen hoechstens einmal je AIB_EVERY laden (aendern sich selten). Je Quelle bleibt die letzte gueltige Fassung im
 * Zwischenspeicher; faellt eine Quelle aus oder liefert Unsinn, gilt die alte weiter (die Liste schrumpft nie auf leer).
 * Nur Konstanten und Funktionen; braucht net_parse/net_merge/net_is_bogon/split46, write_raw/write_mikrotik/write_atomic, index_files aus dem Generator.
 */

const AIB_EVERY     = 20 * 3600;    // Quellen neu laden nach (Sekunden)
const AIB_TIMEOUT   = 30;           // je Abruf
const AIB_MAX_BYTES = 4 << 20;      // je Quelle
const AIB_MAX_NETS  = 5000;         // je Quelle, mehr = Unsinn
const AIB_MIN_V4    = 16;           // kleinstes Praefix (groessere Netze verwerfen)
const AIB_MIN_V6    = 32;
const AIB_UA_MIN    = 50;           // so viele gueltige Kennungen muss ai.robots.txt mindestens liefern
const AIB_UA_MAXLEN = 80;
const AIB_UA_URL    = 'https://raw.githubusercontent.com/ai-robots-txt/ai.robots.txt/main/robots.json';
const AIB_UA_SOURCE = 'https://github.com/ai-robots-txt/ai.robots.txt';
const AIB_UA_LICENSE = 'MIT (ai.robots.txt)';

// id => [Name, URL, Art: crawler | search | user]; user = Abruf auf Anfrage eines Nutzers (ChatGPT-User u. a.)
// Nicht dabei (Begruendung in NEUE-LISTEN-HOCHLADEN.md): Googlebot/Google-Extended, Bingbot, Applebot(-Extended),
// DuckAssistBot (gleiche Datei wie DuckDuckBot) - Netze mit normaler Suche geteilt; Amazonbot, ClaudeBot, Meta,
// Bytespider - keine maschinenlesbare Liste des Betreibers.
const AIB_SOURCES = array(
	'openai_gptbot'      => array('OpenAI GPTBot', 'https://openai.com/gptbot.json', 'crawler'),
	'openai_searchbot'   => array('OpenAI OAI-SearchBot', 'https://openai.com/searchbot.json', 'search'),
	'openai_chatgpt_user' => array('OpenAI ChatGPT-User', 'https://openai.com/chatgpt-user.json', 'user'),
	'perplexity_bot'     => array('PerplexityBot', 'https://www.perplexity.com/perplexitybot.json', 'search'),
	'perplexity_user'    => array('Perplexity-User', 'https://www.perplexity.com/perplexity-user.json', 'user'),
	'commoncrawl_ccbot'  => array('Common Crawl CCBot', 'https://index.commoncrawl.org/ccbot.json', 'crawler'),
	'mistral_user'       => array('MistralAI-User', 'https://mistral.ai/mistralai-user-ips.json', 'user'),
	'google_agent'       => array('Google-Agent (user-triggered AI agents)', 'https://developers.google.com/static/search/apis/ipranges/user-triggered-agents.json', 'user'),
);

/** Eine Adresse laden; false bei Fehler, HTTP-Status ab 400 oder zu gross. */
function aib_get(string $url)
{
	$c = curl_init();
	curl_setopt_array($c, array(
		CURLOPT_URL => $url,
		CURLOPT_RETURNTRANSFER => true,
		CURLOPT_ENCODING => '',
		CURLOPT_FOLLOWLOCATION => true,
		CURLOPT_MAXREDIRS => 5,
		CURLOPT_CONNECTTIMEOUT => 10,
		CURLOPT_TIMEOUT => AIB_TIMEOUT,
		CURLOPT_FAILONERROR => true,
		CURLOPT_USERAGENT => 'IPv64.net-Blocklists/1.0 (+https://ipv64.net/v64_blocklists)',
		CURLOPT_NOPROGRESS => false,
		CURLOPT_XFERINFOFUNCTION => function($ch, $dt, $dn) { return $dn > AIB_MAX_BYTES ? 1 : 0; }, // abbrechen, wenn zu gross
	));
	$r = curl_exec($c);
	curl_close($c);
	return (is_string($r) AND $r !== '' AND strlen($r) <= AIB_MAX_BYTES) ? $r : false;
}

/** Offizielle Liste {"prefixes":[{"ipv4Prefix":..}|{"ipv6Prefix":..}]} -> ['nets'=>[...], 'created'=>?, 'dropped'=>n] oder null */
function aib_parse_ranges(string $raw): ?array
{
	$j = json_decode($raw, true);
	if(!is_array($j) OR !isset($j['prefixes']) OR !is_array($j['prefixes']) OR count($j['prefixes']) > AIB_MAX_NETS) { return null; }
	$nets = array(); $drop = 0;
	foreach($j['prefixes'] as $p) {
		$s = is_array($p) ? ($p['ipv4Prefix'] ?? $p['ipv6Prefix'] ?? null) : null;
		$n = is_string($s) ? net_parse($s) : null;
		// zu grosse Netze (auch 0.0.0.0/0) und nicht routbare Bereiche verwerfen
		if($n === null OR $n['len'] < ($n['v'] === 4 ? AIB_MIN_V4 : AIB_MIN_V6) OR net_is_bogon($n)) { $drop++; continue; }
		$nets[] = $n;
	}
	if(count($nets) === 0) { return null; }
	$created = (isset($j['creationTime']) AND is_string($j['creationTime']) AND strtotime($j['creationTime'])) ? date('c', strtotime($j['creationTime'])) : null;
	return array('nets' => net_merge($nets), 'created' => $created, 'dropped' => $drop);
}

/** Kennung pruefen: druckbares ASCII, 3..AIB_UA_MAXLEN Zeichen, ohne Zeichen, die in robots.txt/nginx/Regex-Listen stoeren. */
function aib_ua_valid(string $t): bool
{
	return strlen($t) >= 3 AND strlen($t) <= AIB_UA_MAXLEN AND preg_match('/^[\x21-\x7E](?:[\x20-\x7E]*[\x21-\x7E])?$/', $t) === 1
		AND strpbrk($t, "\"'\\#;<>`{}|^*$") === false;
}

/** Feld aus robots.json: Text ohne Steuerzeichen, gekuerzt. */
function aib_text($v, int $max): string
{
	if(!is_string($v)) { return ''; }
	$v = trim(preg_replace('/[\x00-\x1F\x7F]+/u', ' ', $v) ?? '');
	return function_exists('mb_substr') ? mb_substr($v, 0, $max) : substr($v, 0, $max);
}

/** Abruf auf Anfrage eines Nutzers (ChatGPT-User, Perplexity-User, Assistenten, Agenten) statt Crawler? */
function aib_ua_user(string $name, string $function): bool
{
	return in_array($function, array('AI Assistants', 'AI Agents', 'AI Coding Agents'), true)
		OR preg_match('/User(?:\/[0-9.]+)?$/', $name) === 1
		OR preg_match('/user[- ](?:prompts?|initiated|request)|on behalf of (?:a |the )?users?/i', $function) === 1;
}

/** robots.json von ai.robots.txt -> Liste ['name','user','operator','function','description','respect','frequency'] oder null */
function aib_parse_ua(string $raw): ?array
{
	$j = json_decode($raw, true);
	if(!is_array($j) OR array_is_list($j)) { return null; }
	$out = array(); $seen = array();
	foreach($j as $name => $f) {
		$name = trim((string)$name);
		if(!aib_ua_valid($name) OR isset($seen[$name]) OR !is_array($f)) { continue; }
		$seen[$name] = true;
		$fn = aib_text($f['function'] ?? '', 200);
		$out[] = array('name' => $name, 'user' => aib_ua_user($name, $fn), 'operator' => aib_text($f['operator'] ?? '', 200), 'function' => $fn,
			'description' => aib_text($f['description'] ?? '', 600), 'respect' => aib_text($f['respect'] ?? '', 200), 'frequency' => aib_text($f['frequency'] ?? '', 200));
	}
	if(count($out) < AIB_UA_MIN) { return null; }
	usort($out, fn($a, $b) => strcasecmp($a['name'], $b['name']) ?: strcmp($a['name'], $b['name']));
	return $out;
}

/** Zwischenspeicher: letzte gueltige Fassung einer Quelle (Dateiname = id). */
function aib_cache_put(string $dir, string $id, string $raw): void
{
	global $dry;
	if($dry OR $dir === '' OR (!is_dir($dir) AND !@mkdir($dir, 0750, true))) { return; }
	$tmp = "$dir/$id.json.tmp";
	if(@file_put_contents($tmp, $raw) === strlen($raw)) { @rename($tmp, "$dir/$id.json"); }
}

/** Quelle laden; gelingt das nicht oder ist der Inhalt ungueltig, die letzte gute Fassung. -> [Ergebnis|null, Stand, Fehler] */
function aib_source(string $dir, string $id, string $url, callable $parse): array
{
	$raw = aib_get($url);
	$res = ($raw === false) ? null : $parse($raw);
	if($res !== null) {
		aib_cache_put($dir, $id, $raw);
		return array($res, time(), '');
	}
	$err = ($raw === false) ? 'download failed' : 'invalid content';
	$p = "$dir/$id.json";
	if($dir !== '' AND is_file($p)) {
		$old = $parse((string)file_get_contents($p));
		if($old !== null) { return array($old, filemtime($p), "$err, last good copy used"); }
	}
	return array(null, null, $err);
}

/** IP-Liste bauen und schreiben; gibt die Angaben je Quelle fuer index.json zurueck (oder null = nichts geschrieben). */
function aib_build_ip(string $OUT, string $dir): ?array
{
	$all = array(); $src = array(); $by = array(); // $by: Netz -> [Netz, Quell-ids] (fuer die Datei mit Quellen)
	foreach(AIB_SOURCES as $id => [$name, $url, $kind]) {
		[$res, $at, $err] = aib_source($dir, $id, $url, 'aib_parse_ranges');
		$e = array('id' => $id, 'name' => $name, 'url' => $url, 'kind' => $kind, 'user' => $kind === 'user', 'ok' => $err === '');
		if($err !== '') { $e['error'] = $err; }
		if($res !== null) {
			[$v4, $v6] = split46($res['nets']);
			$e += array('count' => count($res['nets']), 'count_v4' => count($v4), 'count_v6' => count($v6), 'fetched' => date('c', $at), 'created' => $res['created']);
			foreach($res['nets'] as $n) { $all[] = $n; $k = net_str($n); $by[$k][0] = $n; $by[$k][1][] = $id; }
		}
		$src[] = $e;
		printf("  %-22s %4s %s\n", $id, $res !== null ? count($res['nets']) : '-', $err !== '' ? "($err)" : '');
	}
	if(count($all) === 0) { echo "KI-Bots (IP): keine Quelle verfuegbar, Dateien bleiben wie sie sind\n"; return null; }
	$nets = net_merge($all);
	[$v4, $v6] = split46($nets);
	write_raw("$OUT/ipv64_blocklist_ai_bots.txt", $nets);
	write_raw("$OUT/ipv64_blocklist_v4_ai_bots.txt", $v4);
	write_raw("$OUT/ipv64_blocklist_v6_ai_bots.txt", $v6);
	write_mikrotik("$OUT/v64_mikrotik_v4_ai_bots.rsc", $v4, 4, "IPv64-ai_bots");
	write_mikrotik("$OUT/v64_mikrotik_v6_ai_bots.rsc", $v6, 6, "IPv64-ai_bots");
	// mit Quelle je Netz (enthaltene Netze anderer Quellen zaehlen zum groesseren Netz)
	$s = "# IPv64.net v64 AI Bots (IP) - ".gmdate('Y-m-d H:i')." UTC - https://ipv64.net/v64_blocklists\n# Format: <network> # <source ids>\n";
	foreach($src as $e) { $s .= sprintf("# %-20s %s, %s%s - %s\n", $e['id'], $e['name'], $e['kind'], $e['user'] ? ' (user-triggered)' : '', $e['url']); }
	foreach($nets as $n) {
		$ids = array();
		foreach($by as [$x, $l]) { if(net_contains($n, $x)) { $ids = array_merge($ids, $l); } }
		$s .= net_str($n)." # ".implode(',', array_values(array_unique($ids)))."\n";
	}
	write_atomic("$OUT/ipv64_blocklist_ai_bots_sources.txt", $s);
	printf("%-22s %6d Netze (v4 %6d, v6 %4d) aus %d Quellen\n", "KI-Bots (IP)", count($nets), count($v4), count($v6), count(array_filter($src, fn($e) => isset($e['count']))));
	return $src;
}

/** User-Agent-Liste bauen und schreiben; gibt die Angaben fuer index.json zurueck (oder null = nichts geschrieben). */
function aib_build_ua(string $OUT, string $dir): ?array
{
	[$bots, $at, $err] = aib_source($dir, 'ai_robots_txt', AIB_UA_URL, 'aib_parse_ua');
	if($bots === null) { echo "KI-Bots (User-Agent): ai.robots.txt nicht verfuegbar ($err), Dateien bleiben wie sie sind\n"; return null; }
	$names = array_column($bots, 'name');
	$users = count(array_filter($bots, fn($b) => $b['user']));
	write_atomic("$OUT/ipv64_ai_useragents.txt", implode("\n", $names)."\n");
	write_atomic("$OUT/ipv64_ai_useragents.json", json_encode(array('generated' => date('c'), 'source' => AIB_UA_SOURCE, 'license' => AIB_UA_LICENSE,
		'fetched' => date('c', $at), 'info' => 'https://ipv64.net/v64_blocklists', 'count' => count($bots), 'count_user' => $users,
		'match' => 'case-insensitive token in the User-Agent header; user = fetch on behalf of a user (ChatGPT-User, Perplexity-User, assistants, agents)',
		'bots' => $bots), JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE)."\n");
	$r = "# IPv64.net v64 AI Bots (User-Agent) - ".gmdate('Y-m-d H:i')." UTC - https://ipv64.net/v64_blocklists\n# Source: ".AIB_UA_SOURCE." (".AIB_UA_LICENSE.")\n";
	foreach($names as $n) { $r .= "User-agent: $n\n"; }
	write_atomic("$OUT/ipv64_ai_robots.txt", $r."Disallow: /\n");
	printf("%-22s %6d Kennungen (%d Nutzer-Abrufe)%s\n", "KI-Bots (User-Agent)", count($bots), $users, $err !== '' ? " ($err)" : '');
	return array('fetched' => date('c', $at), 'ok' => $err === '', 'error' => $err, 'count_user' => $users);
}

/**
 * Einstieg: Quellen laden, wenn der letzte Lauf aelter als AIB_EVERY ist (oder $force), sonst nur die index.json-Eintraege
 * aus den vorhandenen Dateien. -> [Eintrag fuer "lists" | null, Eintrag fuer "data" | null]
 */
function aib_run(string $OUT, string $dir, bool $force): array
{
	global $dry;
	$meta_p = "$dir/meta.json";
	$meta = is_file($meta_p) ? json_decode((string)file_get_contents($meta_p), true) : null;
	$fresh = (!$force AND is_array($meta) AND time() - filemtime($meta_p) < AIB_EVERY
		AND is_file("$OUT/ipv64_blocklist_ai_bots.txt") AND is_file("$OUT/ipv64_ai_useragents.json"));
	if(!$fresh) {
		echo "KI-Bots: Quellen laden\n";
		$ip = aib_build_ip($OUT, $dir);
		$ua = aib_build_ua($OUT, $dir);
		$meta = array('ip' => $ip ?? ($meta['ip'] ?? null), 'ua' => $ua ?? ($meta['ua'] ?? null));
		if(!$dry AND $dir !== '' AND (is_dir($dir) OR @mkdir($dir, 0750, true))) { @file_put_contents($meta_p, json_encode($meta, JSON_UNESCAPED_SLASHES)); }
	} else {
		echo "KI-Bots: Quellen juenger als ".(AIB_EVERY / 3600)." h, nur index.json\n";
	}
	$list = null; $data = null;
	$p = "$OUT/ipv64_blocklist_ai_bots.txt";
	if(is_file($p)) {
		$c4 = is_file("$OUT/ipv64_blocklist_v4_ai_bots.txt") ? count(file("$OUT/ipv64_blocklist_v4_ai_bots.txt", FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES)) : 0;
		$c6 = is_file("$OUT/ipv64_blocklist_v6_ai_bots.txt") ? count(file("$OUT/ipv64_blocklist_v6_ai_bots.txt", FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES)) : 0;
		$list = array('id' => 'ai_bots', 'name' => 'v64 AI Bots (IP)', 'category' => 'ai', 'in_all' => false,
			'description' => 'Official IP ranges of AI crawlers and AI fetchers, published by their operators (OpenAI, Perplexity, Common Crawl, Mistral, Google-Agent); includes user-triggered fetchers such as ChatGPT-User and Perplexity-User',
			'source' => 'https://ipv64.net/v64_blocklists', 'license' => 'published by the operators',
			'count' => $c4 + $c6, 'count_v4' => $c4, 'count_v6' => $c6, 'updated' => date('c', filemtime($p)),
			'files' => index_files('', 'ai_bots', true) + array('sources' => 'ipv64_blocklist_ai_bots_sources.txt'),
			'sources' => is_array($meta['ip'] ?? null) ? $meta['ip'] : array());
	}
	$p = "$OUT/ipv64_ai_useragents.txt";
	if(is_file($p)) {
		$files = array('txt' => 'ipv64_ai_useragents.txt');
		foreach(array('json' => 'ipv64_ai_useragents.json', 'robots' => 'ipv64_ai_robots.txt') as $k => $f) { if(is_file("$OUT/$f")) { $files[$k] = $f; } }
		$data = array('id' => 'ai_useragents', 'name' => 'v64 AI Bots (User-Agent)', 'category' => 'ai', 'in_all' => false,
			'description' => 'User agent tokens of AI crawlers, assistants and agents (mirror of ai.robots.txt), one per line; JSON with operator, function and user flag (fetch on behalf of a user); robots.txt block',
			'source' => AIB_UA_SOURCE, 'license' => AIB_UA_LICENSE, 'count' => count(file($p, FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES)),
			'count_user' => (int)($meta['ua']['count_user'] ?? 0), 'updated' => date('c', filemtime($p)), 'files' => $files);
		if(isset($meta['ua']['fetched'])) { $data['fetched'] = $meta['ua']['fetched']; $data['ok'] = (bool)($meta['ua']['ok'] ?? true); }
	}
	return array($list, $data);
}
