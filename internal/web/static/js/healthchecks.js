// Healthchecks: Formular, Liste und Detail-Chart. Vanilla-JS, keine externen Quellen.
(function () {
	"use strict";

	// Formular: nur die Felder des gewaehlten Typs zeigen und absenden
	var typeSel = document.getElementById("hc-type");
	if (typeSel) {
		var update = function () {
			var t = typeSel.value;
			document.querySelectorAll("[data-types]").forEach(function (el) {
				var on = el.getAttribute("data-types").split(" ").indexOf(t) >= 0;
				el.classList.toggle("d-none", !on);
				el.querySelectorAll("input, select, textarea").forEach(function (i) { i.disabled = !on; });
			});
		};
		typeSel.addEventListener("change", update);
		update();
	}

	// Tooltips der Pillen: Inhalt aus data-Attributen, hier maskiert und als HTML gesetzt
	if (window.bootstrap && bootstrap.Tooltip) {
		var esc = function (s) { return String(s).replace(/[&<>"]/g, function (c) { return { "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;" }[c]; }); };
		document.querySelectorAll('[data-bs-toggle="tooltip"]').forEach(function (el) {
			var title = el.getAttribute("data-bs-title") || el.getAttribute("title") || "";
			if (el.hasAttribute("data-tip-label")) {
				var cls = (el.className.match(/beat-(up|down|maintenance|dependent)/) || [])[1] || "";
				title = '<strong class="hc-tip-' + cls + '">' + esc(el.getAttribute("data-tip-label")) + "</strong>";
				if (el.getAttribute("data-tip-ms")) { title += " · " + esc(el.getAttribute("data-tip-ms")); }
				title += "<br>" + esc(el.getAttribute("data-tip-when"));
				if (el.getAttribute("data-tip-msg")) { title += '<br><span class="hc-tip-msg">' + esc(el.getAttribute("data-tip-msg")) + "</span>"; }
			}
			new bootstrap.Tooltip(el, { title: title, html: true, customClass: "hc-tip", container: "body", delay: { show: 80, hide: 0 } });
		});
	}

	// Rueckfrage vor Loeschen und Massenaktionen
	document.querySelectorAll("[data-confirm]").forEach(function (b) {
		b.addEventListener("click", function (e) {
			var form = b.form || b.closest("form");
			if (form && form.id === "hc-bulk") {
				var sel = form.querySelector("select[name=action]");
				if (sel && sel.value !== "delete") { return; }
			}
			if (!window.confirm(b.getAttribute("data-confirm"))) { e.preventDefault(); }
		});
	});

	// Alle auswaehlen
	var all = document.getElementById("hc-select-all");
	if (all) {
		all.addEventListener("change", function () {
			document.querySelectorAll("input[name=tokens]").forEach(function (c) { c.checked = all.checked; });
		});
	}

	// Push-URL in die Zwischenablage
	document.querySelectorAll("[data-copy]").forEach(function (el) {
		el.addEventListener("click", function () {
			el.select();
			if (navigator.clipboard) { navigator.clipboard.writeText(el.value).catch(function () {}); }
		});
	});

	// Latenz-Chart auf der Detailseite
	var canvas = document.getElementById("hc-chart");
	if (canvas && window.Chart) {
		var token = canvas.getAttribute("data-token");
		var chart = null;
		var css = getComputedStyle(document.documentElement);
		var color = function (name, fallback) { return (css.getPropertyValue(name) || fallback).trim(); };
		var load = function (range) {
			fetch("/api/checks/" + token + "/stats?range=" + range, { credentials: "same-origin" })
				.then(function (r) { return r.json(); })
				.then(function (d) {
					var labels = d.series.map(function (b) {
						var t = new Date(b.time);
						return range === "24h" ? t.toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" }) : t.toLocaleDateString([], { day: "2-digit", month: "2-digit" }) + " " + t.toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" });
					});
					var lat = d.series.map(function (b) { return b.count ? b.avg_ms : null; });
					var up = d.series.map(function (b) { return b.count ? b.up_percent : null; });
					var colors = d.series.map(function (b) { return b.up_percent < 100 ? color("--bs-danger", "#dc3545") : color("--bs-primary", "#007bff"); });
					var cfg = {
						type: "line",
						data: {
							labels: labels,
							datasets: [
								{ label: canvas.getAttribute("data-label-latency") + " (ms)", data: lat, borderColor: color("--bs-primary", "#007bff"), backgroundColor: "rgba(0,123,255,.12)", pointBackgroundColor: colors, pointRadius: 2, tension: .25, fill: true, spanGaps: true, yAxisID: "y" },
								{ label: canvas.getAttribute("data-label-up") + " (%)", data: up, borderColor: color("--bs-success", "#28a745"), borderDash: [4, 3], pointRadius: 0, tension: 0, stepped: true, yAxisID: "y1" }
							]
						},
						options: {
							responsive: true, maintainAspectRatio: false, animation: false,
							interaction: { mode: "index", intersect: false },
							scales: {
								y: { beginAtZero: true, title: { display: true, text: "ms" } },
								y1: { position: "right", min: 0, max: 100, grid: { drawOnChartArea: false }, title: { display: true, text: "%" } }
							},
							plugins: { legend: { display: true } }
						}
					};
					if (chart) { chart.destroy(); }
					chart = new Chart(canvas.getContext("2d"), cfg);
				})
				.catch(function () {});
		};
		document.querySelectorAll("#hc-ranges button").forEach(function (b) {
			b.addEventListener("click", function () {
				document.querySelectorAll("#hc-ranges button").forEach(function (x) { x.classList.remove("active"); });
				b.classList.add("active");
				load(b.getAttribute("data-range"));
			});
		});
		load("24h");
	}
})();
