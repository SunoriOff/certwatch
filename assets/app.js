"use strict";
(function () {
  var LABELS = { ok: "OK", warning: "À renouveler", critical: "Critique", invalid: "Invalide", expired: "Expiré", error: "Injoignable" };
  var ORDER = ["error", "expired", "invalid", "critical", "warning", "ok"];
  var data = null, filter = null, open = {}, token = null;
  var $ = function (id) { return document.getElementById(id); };

  function el(tag, cls, text) {
    var e = document.createElement(tag);
    if (cls) e.className = cls;
    if (text != null) e.textContent = text;
    return e;
  }
  function date(ts) { return ts ? new Date(ts * 1000).toLocaleDateString("fr-FR") : "—"; }
  function dateTime(ts) { return ts ? new Date(ts * 1000).toLocaleString("fr-FR") : "jamais"; }

  function load() {
    fetch("/api/status", { cache: "no-store" })
      .then(function (r) { return r.json(); })
      .then(function (j) { data = j; render(); })
      .catch(function () { $("meta").textContent = "Service injoignable."; });
  }

  function render() {
    $("ver").textContent = "v" + data.version;
    var meta = data.scanning ? "Scan en cours…" : "Dernier scan : " + dateTime(data.last_scan);
    $("meta").textContent = meta + " · un scan toutes les " + data.interval_minutes + " min";
    var btn = $("scanBtn");
    btn.hidden = !data.manual_scan;
    btn.disabled = data.scanning;

    var cards = $("cards");
    cards.textContent = "";
    ORDER.slice().reverse().forEach(function (s) {
      var n = data.totals[s] || 0;
      if (!n && s !== "ok") return;
      var c = el("button", "card " + s + (filter === s ? " on" : ""));
      c.type = "button";
      c.appendChild(el("b", null, String(n)));
      c.appendChild(el("span", null, LABELS[s]));
      c.addEventListener("click", function () { filter = filter === s ? null : s; render(); });
      cards.appendChild(c);
    });

    var q = $("q").value.trim().toLowerCase();
    var rows = $("rows");
    rows.textContent = "";
    var shown = data.results.filter(function (r) {
      if (filter && r.status !== filter) return false;
      if (!q) return true;
      var leaf = r.chain[0] || {};
      return [r.name, r.host, r.server_name, String(r.port), leaf.issuer || "", r.tags.join(" "), r.message]
        .join(" ").toLowerCase().indexOf(q) >= 0;
    });
    shown.forEach(function (r) { addRow(rows, r); });
    $("empty").hidden = shown.length > 0;
    $("count").textContent = shown.length + " / " + data.results.length + " cible(s)";
  }

  function addRow(tbody, r) {
    var key = r.host + ":" + r.port;
    var tr = el("tr", "main");
    var td = el("td"); td.appendChild(el("span", "pill " + r.status, LABELS[r.status])); tr.appendChild(td);
    td = el("td");
    td.appendChild(el("div", null, r.name));
    r.tags.forEach(function (t) { td.appendChild(el("span", "tag", t)); });
    tr.appendChild(td);
    td = el("td", "host");
    td.appendChild(el("div", null, r.server_name));
    if (r.server_name !== r.host) td.appendChild(el("div", "sub", key));
    tr.appendChild(td);
    tr.appendChild(el("td", "num", r.days_remaining == null ? "—" : String(r.days_remaining)));
    tr.appendChild(el("td", null, date(r.expires_at)));
    tr.appendChild(el("td", null, (r.chain[0] && r.chain[0].issuer) || "—"));
    tr.appendChild(el("td", null, r.message));
    tr.addEventListener("click", function () { open[key] = !open[key]; render(); });
    tbody.appendChild(tr);
    if (open[key]) tbody.appendChild(detail(r));
  }

  function detail(r) {
    var tr = el("tr", "detail"), td = el("td");
    td.colSpan = 7;
    if (r.issues.length) {
      var ul = el("ul", "issues");
      r.issues.forEach(function (i) { ul.appendChild(el("li", null, i)); });
      td.appendChild(ul);
    }
    if (r.tls_version) td.appendChild(el("p", null, r.tls_version + " · " + (r.cipher_suite || "") + " · " + r.duration_ms + " ms"));
    var chain = el("div", "chain");
    r.chain.forEach(function (c, i) {
      var box = el("div", "cert");
      box.appendChild(el("h4", null, i === 0 ? "Certificat du site" : (c.subject === c.issuer ? "Racine (auto-signée)" : "Intermédiaire " + i)));
      var dl = el("dl");
      [["Sujet", c.subject], ["Émetteur", c.issuer], ["Valide du", date(c.not_before)], ["au", date(c.not_after)],
       ["Clé", c.key], ["Signature", c.signature_algorithm], ["Noms", c.dns_names.join(", ") || "—"], ["Série", c.serial]]
        .forEach(function (kv) { dl.appendChild(el("dt", null, kv[0])); dl.appendChild(el("dd", null, kv[1])); });
      box.appendChild(dl);
      chain.appendChild(box);
    });
    td.appendChild(chain);
    tr.appendChild(td);
    return tr;
  }

  $("q").addEventListener("input", function () { if (data) render(); });
  $("scanBtn").addEventListener("click", function () {
    if (!token) token = window.prompt("Jeton d'API (api_token) :");
    if (!token) return;
    fetch("/api/scan", { method: "POST", headers: { Authorization: "Bearer " + token } })
      .then(function (r) {
        if (r.status === 401) { token = null; alert("Jeton refusé."); }
        setTimeout(load, 800);
      });
  });
  load();
  setInterval(load, 30000);
})();
