# DynDNS-Seite: CDN64-Einträge schützen und anzeigen (ipv64.net)

Beim Live-Test von Modus 3 aufgefallen:

- Die Einträge der Server (A/AAAA auf srv07/srv08, `cdn_tmp = 3`) erscheinen in `dyndns.php` als normale
  „Valid“-Einträge mit Bearbeiten und Löschen; auch **Domain Reset** löscht sie – danach zeigt der Name nicht mehr auf
  die Server, CDN64 ist kaputt.
- Der deaktivierte Original-Eintrag zeigt nur „Deactivated“ statt „CDN“ (er ist schon geschützt: `del_record()`
  löscht keine deaktivierten Einträge).
- In der Domain-Übersicht fehlt das Abzeichen „CDN“ für Domains mit CDN64.

API v2 ist bereits richtig (`record_locked()` sperrt `cdn_tmp != 0`).

## 1. `dbconnect.php`, `del_record()`: nie CDN-Einträge löschen

VORHER:

```php
	if($domainss["id"] != "" AND $recordid != "" AND $domainss["deactivated"] != 1 AND $domainss["cdn_token"] == 0 AND !$in_failover)
```

NACHHER:

```php
	if($domainss["id"] != "" AND $recordid != "" AND $domainss["deactivated"] != 1 AND $domainss["cdn_token"] == 0 AND (int)$domainss["cdn_tmp"] === 0 AND !$in_failover)
```

(Damit scheitert auch „Bearbeiten“ eines solchen Eintrags, denn Bearbeiten = Löschen + neu Anlegen.)

## 2. `dyndns.php`, Domain Reset: CDN-Einträge stehen lassen

VORHER:

```php
			$statement = $pdo->prepare("SELECT id FROM subdomain_records WHERE userid = :userid AND subdomain_id = :subdomain AND deactivated = :da");
```

NACHHER:

```php
			$statement = $pdo->prepare("SELECT id FROM subdomain_records WHERE userid = :userid AND subdomain_id = :subdomain AND deactivated = :da AND cdn_tmp = 0");
```

VORHER:

```php
				$statement = $pdo->prepare("DELETE FROM subdomain_records WHERE userid = :userid AND subdomain_id = :subdomain AND deactivated = :da");
```

NACHHER:

```php
				$statement = $pdo->prepare("DELETE FROM subdomain_records WHERE userid = :userid AND subdomain_id = :subdomain AND deactivated = :da AND cdn_tmp = 0");
```

## 3. `dyndns.php`, Liste der Einträge: Abzeichen „CDN64“, ohne Bearbeiten/Löschen

VORHER (vor der Schleife über die Einträge):

```php
					    $statement = $pdo->prepare("SELECT * FROM subdomain_records WHERE userid = :userid AND subdomain_id = :sdid ORDER BY praefix,type");
						$result = $statement->execute(array('userid' => $userid,'sdid' => $domains["id"]));
						$records = $statement->fetchAll();
```

NACHHER:

```php
					    $statement = $pdo->prepare("SELECT * FROM subdomain_records WHERE userid = :userid AND subdomain_id = :sdid ORDER BY praefix,type");
						$result = $statement->execute(array('userid' => $userid,'sdid' => $domains["id"]));
						$records = $statement->fetchAll();
						// CDN64: Original (deaktiviert, Ziel) und Server-Eintraege des Namens
						$c64 = array();
						$st64 = $pdo->prepare("SELECT r.record_id, r.role FROM cdn64o_records r JOIN cdn64o_hosts h ON h.id = r.host_id WHERE h.userid = :u AND h.subdomain_id = :s");
						$st64->execute(array('u' => $userid, 's' => $domains["id"]));
						foreach($st64->fetchAll() as $x) { $c64[$x["record_id"]] = $x["role"]; }
```

VORHER:

```php
						if($record["update_dns"] == "1"){$valid = "<span class=\"badge badge-warning\">Updating..</span>";}
```

NACHHER:

```php
						if(isset($c64[$record["id"]])) { $valid = $c64[$record["id"]] === "edge" ? "<span class=\"badge badge-info\">CDN64 Server</span>" : "<span class=\"badge badge-info\">CDN64 Active</span>"; }
						if($record["update_dns"] == "1"){$valid = "<span class=\"badge badge-warning\">Updating..</span>";}
						$c64lock = isset($c64[$record["id"]]) || (int)$record["cdn_tmp"] !== 0;
```

VORHER (Bearbeiten und Löschen am Ende der Zeile):

```php
								  echo "
								  <a href=\"?edit=$subdomain&rr=$record[id]\">
									<i class=\"fa fa-edit text-primary\" data-toggle=\"tooltip\" data-placement=\"top\" title=\"Edit this Domain Record\"></i>
								  </a>
								  <td>&nbsp;&nbsp;
									  <a class=\"text-reset me-3\" href=\"#\" data-toggle=\"modal\" data-target=\"#confirmDeleteModal\" data-delete-url=\"?edit=$subdomain&del=$record[id]\">
										<i class=\"fa fa-trash text-danger\"></i>
									  </a>
								  </td>
								</tr>
							";
```

NACHHER:

```php
								  if($c64lock) {
								  echo "
								  <i class=\"fa-solid fa-lock text-muted\" data-toggle=\"tooltip\" data-placement=\"top\" title=\"Managed by CDN64 – switch CDN64 off for this name first.\"></i>
								  <td></td>
								</tr>
							";
								  } else {
								  echo "
								  <a href=\"?edit=$subdomain&rr=$record[id]\">
									<i class=\"fa fa-edit text-primary\" data-toggle=\"tooltip\" data-placement=\"top\" title=\"Edit this Domain Record\"></i>
								  </a>
								  <td>&nbsp;&nbsp;
									  <a class=\"text-reset me-3\" href=\"#\" data-toggle=\"modal\" data-target=\"#confirmDeleteModal\" data-delete-url=\"?edit=$subdomain&del=$record[id]\">
										<i class=\"fa fa-trash text-danger\"></i>
									  </a>
								  </td>
								</tr>
							";
								  }
```

## 4. `dyndns.php`, Domain-Übersicht: Abzeichen „CDN64“ (zwei Stellen)

An **beiden** Stellen mit `// 4. CDN Domains des Users`:

VORHER:

```php
						foreach($st->fetchAll(PDO::FETCH_ASSOC) as $r) { $cdns[$r['domainid']] = $r['status']; }
```

NACHHER:

```php
						foreach($st->fetchAll(PDO::FETCH_ASSOC) as $r) { $cdns[$r['domainid']] = $r['status']; }
						$cdn64 = [];
						$st = $pdo->prepare("SELECT DISTINCT subdomain_id FROM cdn64o_hosts WHERE userid = ? AND status IN ('active','blocked','pending')");
						$st->execute([$userid]);
						foreach($st->fetchAll(PDO::FETCH_ASSOC) as $r) { $cdn64[$r['subdomain_id']] = true; }
```

Und an **beiden** Stellen mit `// --- CDN (war Query 4) ---`:

VORHER:

```php
							if((int)($cdns[$domain["id"]] ?? 0) !== 0) {
								$cdn = " <span class=\"badge badge-info\">CDN</span>";
							}
```

NACHHER:

```php
							if((int)($cdns[$domain["id"]] ?? 0) !== 0) {
								$cdn = " <span class=\"badge badge-info\">CDN</span>";
							}
							if(isset($cdn64[$domain["id"]])) {
								$cdn .= " <span class=\"badge badge-info\">CDN64</span>";
							}
```
