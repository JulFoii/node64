<?php 
include("/var/www/clients/client1/web58/web/dbconnect.php");

/** IPv4- und IPv6-Adressen aus Text oder JSON (Tor: Onionoo "1.2.3.4:9001", "[2001:db8::1]:9001", exit_addresses). */
function tor_ips(string $text): array
{
	$ips = array();
	preg_match_all('/(?<![0-9.])\d{1,3}(?:\.\d{1,3}){3}(?![0-9.])/', $text, $m4);
	preg_match_all('/(?<![0-9A-Fa-f:])(?:[0-9A-Fa-f]{0,4}:){2,7}[0-9A-Fa-f]{0,4}(?![0-9A-Fa-f:])/', $text, $m6);
	foreach(array_merge($m4[0], $m6[0]) as $ip) { if(filter_var($ip, FILTER_VALIDATE_IP)) { $ips[] = $ip; } }
	return array_values(array_unique($ips));
}

/** Adressen und Netze (mit /Praefix) aus Text oder JSON, fuer alle Listen ohne eigenen Leser unten. */
function net_tokens(string $text): array
{
	$ips = array();
	preg_match_all('/(?<![0-9.])\d{1,3}(?:\.\d{1,3}){3}(?:\/\d{1,2})?(?![0-9.])/', $text, $m4);
	preg_match_all('/(?<![0-9A-Fa-f:])(?:[0-9A-Fa-f]{0,4}:){2,7}[0-9A-Fa-f]{0,4}(?:\/\d{1,3})?(?![0-9A-Fa-f:])/', $text, $m6);
	foreach(array_merge($m4[0], $m6[0]) as $ip) { if(filter_var(explode("/", $ip)[0], FILTER_VALIDATE_IP)) { $ips[] = $ip; } }
	return array_values(array_unique($ips));
}

/** Eine Adresse laden; false bei Fehler oder HTTP-Status ab 400. */
function bl_get(string $url)
{
	$curl = curl_init();
	curl_setopt_array($curl, array(
	  CURLOPT_URL => $url,
	  CURLOPT_RETURNTRANSFER => true,
	  CURLOPT_ENCODING => '',
	  CURLOPT_MAXREDIRS => 10,
	  CURLOPT_TIMEOUT => 60,
	  CURLOPT_FOLLOWLOCATION => true,
	  CURLOPT_FAILONERROR => true,
	  CURLOPT_HTTP_VERSION => CURL_HTTP_VERSION_1_1,
	  CURLOPT_CUSTOMREQUEST => 'GET',
	));
	$response = curl_exec($curl);
	curl_close($curl);
	return $response;
}

// Listen mit eigenem Leser unten; alle anderen laufen ueber net_tokens()
$eigene_leser = array("spamhaus_drop", "firehole_l1", "blocklistde_all", "dshield1", "tor_exit", "tor_all");

$statement = $pdo->prepare("SELECT * FROM blocklisten");
$result = $statement->execute();
$blocklisten = $statement->fetchAll();
foreach($blocklisten as $blockliste)
{
	
	$ipCount = 0;
	echo $blockliste["name"]." wird aktualisiert.\n";
	// url kann mehrere Adressen enthalten (durch Leerzeichen getrennt, z. B. v4 und v6); alle muessen klappen
	$response = '';
	foreach(preg_split('/\s+/', trim($blockliste["url"])) as $u)
	{
		$r = bl_get($u);
		if($r === false) { $response = false; break; }
		$response .= $r."\n";
	}

	//print_r($response);

	$eigener_leser = in_array($blockliste["file_name"], $eigene_leser);
	if($response === false OR ($eigener_leser AND strlen($response) < 1000)) { echo "  Download fehlgeschlagen, Liste bleibt unveraendert.\n"; continue; }
	if(!$eigener_leser)
	{
		// kleine Listen (Cloudflare, Feodo) sind gueltig; leer heisst Fehler
		$ips = net_tokens($response);
		if(count($ips) < 1) { echo "  Keine Adressen gefunden, Liste bleibt unveraendert.\n"; continue; }
	}
	$statement = $pdo->prepare("TRUNCATE TABLE $blockliste[db_name]");
	$result = $statement->execute();

	if($blockliste["file_name"] == "spamhaus_drop")
	{
		//Hole auch die v6 Liste
		$curl = curl_init();
		curl_setopt_array($curl, array(
		  CURLOPT_URL => "https://www.spamhaus.org/drop/drop_v6.json",
		  CURLOPT_RETURNTRANSFER => true,
		  CURLOPT_ENCODING => '',
		  CURLOPT_MAXREDIRS => 10,
		  CURLOPT_TIMEOUT => 60,
		  CURLOPT_FOLLOWLOCATION => true,
		  CURLOPT_HTTP_VERSION => CURL_HTTP_VERSION_1_1,
		  CURLOPT_CUSTOMREQUEST => 'GET',
		));
		$responsev6 = curl_exec($curl);
		curl_close($curl);
		
		$response .= "\n";
		$response .= $responsev6;
		$ips = array();
		
		foreach (explode("\n", $response) as $line) {
			
			$data = json_decode(trim($line));
			if (isset($data->cidr)) {
				$ips[] = $data->cidr;
				//echo $data->cidr;
			}
		}
		$ips = array_values(array_unique($ips));
		foreach($ips as $ip) {
			$ip = checkipsubnet($ip);
			
			$statement = $pdo->prepare("INSERT INTO $blockliste[db_name] (ip) VALUES (:ip)");
			$result = $statement->execute(array('ip'=> $ip));
		}
		
	}
	if($blockliste["file_name"] == "firehole_l1" OR $blockliste["file_name"] == "blocklistde_all")
	{
		$response = explode("\n",$response);
		$ips = array();
		foreach($response as $resp)
		{
			$ip_a = explode("/",$resp);
			if(filter_var($ip_a[0], FILTER_VALIDATE_IP, FILTER_FLAG_IPV4) OR filter_var($ip_a[0], FILTER_VALIDATE_IP, FILTER_FLAG_IPV6))
			{
				array_push($ips,$resp);
			}
		}
		$ips = array_values(array_unique($ips));
		foreach($ips as $ip) {
			$ip = checkipsubnet($ip);
			$statement = $pdo->prepare("INSERT INTO $blockliste[db_name] (ip) VALUES (:ip)");
			$result = $statement->execute(array('ip'=> $ip));
		}		
	}
	if($blockliste["file_name"] == "dshield1")
	{
		// Regulärer Ausdruck für die Extraktion der IP-Adressen
		$pattern = '/(\d{1,3}\.\d{1,3}\.\d{1,3}\.0)/';
		// Suchen nach Übereinstimmungen im Text
		preg_match_all($pattern, $response, $matches);
		// Ausgabe der gefundenen IP-Adressen
		$ips = array();
		foreach ($matches[0] as $ip) {
			$ip_sub = $ip."/24";
			if(filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4) OR filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV6))
			{	
				array_push($ips,$ip_sub);
			}
		}
		$ips = array_values(array_unique($ips));
		foreach($ips as $ip) {
			$ip = checkipsubnet($ip);
			//$ipCount += countValidIPsInSubnet($ip);
			$statement = $pdo->prepare("INSERT INTO $blockliste[db_name] (ip) VALUES (:ip)");
			$result = $statement->execute(array('ip'=> $ip));
		}
	}
	if($blockliste["file_name"] == "tor_exit" OR $blockliste["file_name"] == "tor_all")
	{
		// IPv4 und IPv6 (Quelle: Onionoo des Tor-Projekts, JSON)
		$ips = tor_ips($response);
		foreach($ips as $ip) {
			$ip = checkipsubnet($ip);
			//$ipCount += countValidIPsInSubnet($ip);
			$statement = $pdo->prepare("INSERT INTO $blockliste[db_name] (ip) VALUES (:ip)");
			$result = $statement->execute(array('ip'=> $ip));
		}

	}
	if(!$eigener_leser)
	{
		foreach($ips as $ip) {
			$ip = checkipsubnet($ip);
			$statement = $pdo->prepare("INSERT INTO $blockliste[db_name] (ip) VALUES (:ip)");
			$result = $statement->execute(array('ip'=> $ip));
		}
	}
	$ipCount = count($ips);
	$ips = "";
	$ip = "";
	$date = date("Y-m-d H:i:s");
	
	$statement = $pdo->prepare("UPDATE blocklisten set last_updated = :date, ips = :ips WHERE id = :id");
	$result = $statement->execute(array('date' => "$date",'ips' => "$ipCount",'id' => $blockliste["id"]));
}


?>