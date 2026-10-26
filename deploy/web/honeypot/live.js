// Honeypot64 – Live-Karte auf ipv64.net (live.php): Weltkarte aus worldmap.json, Angriffe aus live.json (statisch, alle
// 2 Minuten neu). Neue Eintraege zuerst als Bogen, sonst werden aeltere aus der letzten Stunde wiederholt (blasser);
// die Tabelle zeigt nur echte Eintraege.
(function () {
	"use strict";
	var T = window.HL_T || {}, lang = window.HL_LANG || "de";
	var NS = "http://www.w3.org/2000/svg";
	var land = document.getElementById("hlLand"), arcs = document.getElementById("hlArcs"), table = document.getElementById("hlTable");
	var pauseBtn = document.getElementById("hlPause");
	var reduce = window.matchMedia && window.matchMedia("(prefers-reduced-motion: reduce)").matches;
	var names = window.Intl && Intl.DisplayNames ? new Intl.DisplayNames([lang], { type: "region" }) : null;
	var tf = new Intl.DateTimeFormat(lang, { hour: "2-digit", minute: "2-digit" });
	var nf = new Intl.NumberFormat(lang);
	var map = null, entries = [], fresh = [], seen = 0, running = true, replay = 0, shownIds = {};

	function name(cc) { try { return names ? names.of(cc) : cc; } catch (e) { return cc; } }
	function flag(cc) { return /^[A-Z]{2}$/.test(cc) ? String.fromCodePoint(0x1F1E6 + cc.charCodeAt(0) - 65, 0x1F1E6 + cc.charCodeAt(1) - 65) : ""; }
	function el(n, a) { var e = document.createElementNS(NS, n); Object.keys(a || {}).forEach(function (k) { e.setAttribute(k, a[k]); }); return e; }
	function pt(cc) { var c = map && map.countries[cc]; return c ? [c.x, c.y] : null; }

	function drawLand(byCountry) {
		land.replaceChildren();
		var max = 0;
		Object.keys(byCountry || {}).forEach(function (k) { max = Math.max(max, byCountry[k]); });
		Object.keys(map.countries).forEach(function (cc) {
			var n = (byCountry || {})[cc] || 0;
			// Stufen 1-5 logarithmisch wie in Node64 (staerkstes Land = 5)
			var lvl = n <= 0 ? 0 : (max <= 1 ? 5 : Math.min(5, 1 + Math.floor(4.999 * Math.log(n) / Math.log(max))));
			var p = el("path", { d: map.countries[cc].d, "class": lvl ? "hl-m" + lvl : "" });
			var t = el("title");
			t.textContent = flag(cc) + " " + name(cc) + (n ? ": " + nf.format(n) + " " + T.attacks : "");
			p.appendChild(t);
			land.appendChild(p);
		});
	}

	function tip(e, rep) {
		return flag(e.cc) + " " + name(e.cc) + " (" + e.src + ") → " + flag(e.dst) + " " + name(e.dst) + " · " + e.kind + " · " + e.svc.toUpperCase() +
			(e.port ? " " + e.port : "") + " · " + tf.format(new Date(e.t)) + (rep ? " (" + T.replay + ")" : "");
	}

	function arc(e, rep) {
		var a = pt(e.cc), b = pt(e.dst);
		if (!a || !b) { return; }
		var x1 = a[0], y1 = a[1], x2 = b[0], y2 = b[1], dx = x2 - x1, dy = y2 - y1, dist = Math.sqrt(dx * dx + dy * dy);
		if (dist < 3) { x1 += 14; y1 -= 10; dist = 17; } // Angreifer im Land des Sensors
		var cx = (x1 + x2) / 2, cy = (y1 + y2) / 2 - Math.max(18, dist * 0.35);
		var p = el("path", { d: "M" + x1 + " " + y1 + " Q" + cx + " " + cy + " " + x2 + " " + y2, "class": "hl-arc hl-g-" + e.group + (rep ? " hl-replay" : "") });
		var t = el("title"); t.textContent = tip(e, rep); p.appendChild(t);
		var dot = el("circle", { cx: a[0], cy: a[1], r: 2.2, "class": "hl-src hl-g-" + e.group });
		var ring = el("circle", { cx: x2, cy: y2, r: 4, "class": "hl-dst" });
		arcs.append(p, dot, ring);
		var gone = function () { p.remove(); dot.remove(); ring.remove(); };
		if (!reduce && p.animate && p.getTotalLength) {
			var len = p.getTotalLength();
			p.style.strokeDasharray = len;
			p.animate([{ strokeDashoffset: len, opacity: 1 }, { strokeDashoffset: 0, opacity: 1, offset: 0.55 }, { strokeDashoffset: 0, opacity: 0 }],
				{ duration: 2800, easing: "ease-out" }).onfinish = gone;
		} else {
			setTimeout(gone, 2800);
		}
	}

	function renderTable(list) {
		table.replaceChildren();
		if (!list.length) {
			var tr0 = document.createElement("tr"), td0 = document.createElement("td");
			td0.colSpan = 6; td0.className = "text-muted"; td0.textContent = T.empty;
			tr0.appendChild(td0); table.appendChild(tr0);
			return;
		}
		list.slice(0, 40).forEach(function (e) {
			var id = e.t + "|" + e.src + "|" + e.kind + "|" + e.port + "|" + e.dst;
			var tr = document.createElement("tr");
			if (seen && !shownIds[id]) { tr.className = "hl-new"; }
			shownIds[id] = true;
			var sw = '<span class="hl-sw hl-g-' + e.group + '"></span> ';
			[tf.format(new Date(e.t)), flag(e.cc) + " " + e.src, sw + e.kind, e.svc.toUpperCase() + (e.port ? " " + e.port : ""), flag(e.dst) + " " + name(e.dst), nf.format(e.n)].forEach(function (v, i) {
				var td = document.createElement("td");
				if (i === 2) { td.innerHTML = sw; td.appendChild(document.createTextNode(e.kind)); } else { td.textContent = v; }
				if (i === 1) { td.style.fontFamily = "monospace"; }
				if (i === 5) { td.className = "text-right"; }
				tr.appendChild(td);
			});
			table.appendChild(tr);
		});
	}

	function stats(s) {
		var set = function (k, v) { var x = document.querySelector('[data-hl-stat="' + k + '"]'); if (x) { x.textContent = v; } };
		set("events", nf.format(s.events || 0));
		set("sources", nf.format(s.sources || 0));
		set("targets", nf.format(s.targets || 0));
		var top = (s.countries || [])[0];
		set("top", top ? flag(top[0]) + " " + name(top[0]) : "–");
	}

	function load() {
		return fetch("live.json?t=" + Math.floor(Date.now() / 60000), { cache: "no-store" }).then(function (r) { if (!r.ok) { throw new Error(r.status); } return r.json(); }).then(function (d) {
			var list = d.entries || [];
			var max = seen;
			list.forEach(function (e) { if (seen && e.t > seen) { fresh.push(e); } if (e.t > max) { max = e.t; } });
			entries = list.slice().reverse();
			drawLand((d.stats || {}).by_country);
			stats(d.stats || {});
			renderTable(list);
			seen = max || 1;
			document.getElementById("hlUpdated").textContent = (T.updated || "").replace("{time}", new Date(d.generated).toLocaleString(lang));
		}).catch(function () { document.getElementById("hlUpdated").textContent = T.unavailable; });
	}

	function tick() {
		if (!running || document.hidden || !map) { return; }
		if (fresh.length) { arc(fresh.shift(), false); return; }
		if (entries.length) { arc(entries[replay++ % entries.length], true); }
	}

	pauseBtn.addEventListener("click", function () {
		running = !running;
		pauseBtn.innerHTML = running ? '<i class="fa-solid fa-pause"></i> ' + T.pause : '<i class="fa-solid fa-play"></i> ' + T.play;
		document.getElementById("hlLiveBadge").className = "badge align-middle small " + (running ? "badge-danger" : "badge-secondary");
		if (!running) { arcs.replaceChildren(); }
	});
	fetch("worldmap.json", { cache: "force-cache" }).then(function (r) { return r.json(); }).then(function (m) {
		map = m;
		document.getElementById("hlMap").setAttribute("viewBox", m.viewBox);
		drawLand({});
		load();
		setInterval(tick, 900);
		setInterval(function () { if (!document.hidden) { load(); } }, 60000);
	});
})();
