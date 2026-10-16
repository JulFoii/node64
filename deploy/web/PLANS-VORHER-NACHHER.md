# API v2: öffentlicher Endpunkt `GET /plans` (Account-Klassen)

Node64 zeigt unter **Account-Klassen** (`/plans`) die Klassen von ipv64.net mit Preis und Grenzen an. Die Daten holt
es einmal am Tag von `https://ipv64.net/api/v2/plans`, ohne API-Key. Solange es den Endpunkt nicht gibt, zeigt Node64
einen eingebauten Stand (Werte aus `user_class`, Stand 2026-10-16) und verlinkt die Preisseite.

Die Werte kommen live aus `user_class`, also derselben Quelle wie `pricing.php`. Die Preise und Anzeigenamen stehen
hier so wie auf der Preisseite. Ändern sich die Preise, muss man sie an beiden Stellen anpassen.

## Datei `api_v2.php`

### Vorher

```php
route('GET', '/ip', function() {
	$ip = client_ip();
	ok(array('ip' => $ip, 'family' => filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV6) ? 'ipv6' : 'ipv4'));
}, true);
```

### Nachher

```php
route('GET', '/ip', function() {
	$ip = client_ip();
	ok(array('ip' => $ip, 'family' => filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV6) ? 'ipv6' : 'ipv4'));
}, true);

// Account-Klassen wie auf der Preisseite (oeffentlich): Grenzen live aus user_class, null = unbegrenzt
route('GET', '/plans', function() {
	$plans = array(
		array(1, 'free',      'Free',             0,   'https://ipv64.net/account'),
		array(6, 'supporter', 'Home / Supporter', 40,  'https://ipv64.net/account?account_class&type=supporter'),
		array(4, 'business',  'Business',         100, 'https://ipv64.net/account?account_class&type=business'),
		array(5, 'company',   'Company',          200, 'https://ipv64.net/account?account_class&type=company'),
	);
	$n = fn($v) => (int)$v;
	$u = fn($v) => (int)$v > 0 ? (int)$v : null; // 0 = unbegrenzt
	$out = array();
	foreach($plans as $p) {
		$c = q1("SELECT * FROM user_class WHERE id = :id", array('id' => $p[0]));
		if(!$c) { continue; }
		$out[] = array('id' => $p[0], 'key' => $p[1], 'name' => $p[2], 'class_name' => $c['name'], 'price_year_eur' => $p[3], 'upgrade_url' => $p[4],
			'limits' => array(
				'dyndns_domains' => $n($c['dyndns_limit']), 'own_domains' => $n($c['owndomain_limit']), 'dyndns_updates_24h' => $u($c['dyndns_update_limit']),
				'dyndns_ttl_s' => $n($c['ttl']), 'healthchecks' => $n($c['healthcheck_limit']), 'healthcheck_pings_24h' => $u($c['healthcheck_update_limit']),
				'sms_24h' => $u($c['sms_limit']), 'statistics_days' => $n($c['statistics_time']),
				'failover_policies' => $n($c['failover_policies']), 'failover_monitors' => $n($c['failover_monitors']), 'failover_rules' => $n($c['failover_rules']),
				'offline_pages' => $n($c['offline_pages']), 'cdn_domains' => $n($c['cdn_domains']), 'cdn_traffic_gb' => $n($c['cdn_traffic']),
				'cdn_mappings' => $n($c['cdn_mappings']), 'cloud_routers' => $n($c['cloud_router']), 'vpn_gateways' => $n($c['vpn_gateways']),
				'vpn_peers' => $n($c['vpn_peers']), 'vpn_traffic_gb' => $n($c['vpn_traffic']), 'dns64_clients' => $n($c['dns64_clients']),
				'log_days' => $n($c['log_days']),
			));
	}
	header('Cache-Control: public, max-age=3600');
	ok($out, 200, array('pricing_url' => 'https://ipv64.net/pricing'));
}, true);
```

## Prüfen

```bash
curl -s https://ipv64.net/api/v2/plans | head -c 400
```

Erwartet wird `{"data":[{"id":1,"key":"free","name":"Free","class_name":"Standard",…` mit vier Einträgen. Node64 holt
die Daten beim nächsten Aufruf der Seite **Account-Klassen**, spätestens nach einem Tag. Den eingebauten Stand ersetzt
es dann von selbst.
