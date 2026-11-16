"use strict";
// Alle dynamischen Inhalte werden per textContent gesetzt (kein innerHTML) -> kein XSS.

const $ = (s) => document.querySelector(s);
const state = { token: sessionStorage.getItem("token"), user: sessionStorage.getItem("user"),
                role: sessionStorage.getItem("role"), offset: 0, limit: 15, total: 0 };

function el(tag, attrs = {}, ...children) {
  const node = document.createElement(tag);
  for (const [k, v] of Object.entries(attrs)) {
    if (k === "class") node.className = v;
    else if (k === "text") node.textContent = v;
    else node.setAttribute(k, v);
  }
  for (const c of children) node.append(c);
  return node;
}

async function api(path, options = {}) {
  const headers = { "Content-Type": "application/json" };
  if (state.token) headers.Authorization = "Bearer " + state.token;
  const res = await fetch(path, { ...options, headers });
  if (res.status === 401 && state.token) { logout(); throw new Error("Sitzung abgelaufen"); }
  if (!res.ok) {
    let msg = res.statusText;
    try { const d = await res.json(); msg = typeof d.detail === "string" ? d.detail : JSON.stringify(d.detail); } catch (_) {}
    throw new Error(msg);
  }
  return res.status === 204 ? null : res.json();
}

// ---------- Auth ----------
function showApp() {
  const loggedIn = !!state.token;
  $("#login-view").classList.toggle("hidden", loggedIn);
  $("#app-view").classList.toggle("hidden", !loggedIn);
  if (loggedIn) { $("#whoami").textContent = `${state.user} (${state.role})`; loadDashboard(); }
}

function logout() {
  sessionStorage.clear();
  state.token = null;
  showApp();
}

$("#login-form").addEventListener("submit", async (e) => {
  e.preventDefault();
  $("#login-error").textContent = "";
  try {
    const d = await api("/api/auth/login", { method: "POST",
      body: JSON.stringify({ username: $("#username").value, password: $("#password").value }) });
    state.token = d.access_token; state.user = d.username; state.role = d.role;
    sessionStorage.setItem("token", d.access_token);
    sessionStorage.setItem("user", d.username);
    sessionStorage.setItem("role", d.role);
    $("#password").value = "";
    showApp();
  } catch (err) { $("#login-error").textContent = err.message; }
});
$("#logout").addEventListener("click", logout);

// ---------- Tabs ----------
document.querySelectorAll(".tab").forEach((btn) => btn.addEventListener("click", () => {
  document.querySelectorAll(".tab").forEach((b) => b.classList.toggle("active", b === btn));
  for (const name of ["dashboard", "alerts", "rules"])
    $("#tab-" + name).classList.toggle("hidden", name !== btn.dataset.tab);
  if (btn.dataset.tab === "dashboard") loadDashboard();
  if (btn.dataset.tab === "alerts") loadAlerts();
  if (btn.dataset.tab === "rules") loadRules();
}));

// ---------- Dashboard ----------
function barChart(container, rows, cls = () => "") {
  container.replaceChildren();
  const max = Math.max(1, ...rows.map((r) => r.value));
  for (const r of rows) {
    const bar = el("div", { class: "bar " + cls(r) });
    bar.style.width = Math.max(2, (r.value / max) * 100) + "%";
    container.append(el("div", { class: "row" }, el("span", { class: "name", text: r.label }), bar,
      el("span", { text: String(r.value) })));
  }
  if (!rows.length) container.append(el("em", { text: "Keine Daten" }));
}

async function loadDashboard() {
  try {
    const s = await api("/api/stats");
    $("#kpis").replaceChildren(
      ...[["Gesamt", s.total], ["Neu", s.by_status.new || 0], ["In Bearbeitung", s.by_status.investigating || 0],
          ["Kritisch", s.by_severity.critical || 0]].map(([l, n]) =>
        el("div", { class: "card kpi" }, el("div", { class: "num", text: String(n) }), el("div", { class: "lbl", text: l }))));
    barChart($("#chart-days"), s.per_day.map((d) => ({ label: d.day.slice(5), value: d.count })));
    barChart($("#chart-sev"), ["critical", "high", "medium", "low"].map((k) => ({ label: k, value: s.by_severity[k] || 0 })),
      (r) => "sev-" + r.label);
    $("#top-ips").replaceChildren(...s.top_source_ips.map((i) => el("li", { text: `${i.ip} (${i.count})` })));
    $("#top-mitre").replaceChildren(...s.top_mitre.map((m) => el("li", { text: `${m.id} ${m.name} (${m.count})` })));
  } catch (err) { console.error(err); }
}

// ---------- Alerts ----------
async function loadAlerts() {
  const p = new URLSearchParams({ limit: state.limit, offset: state.offset, sort: $("#f-sort").value });
  if ($("#f-q").value) p.set("q", $("#f-q").value);
  if ($("#f-sev").value) p.set("severity", $("#f-sev").value);
  if ($("#f-status").value) p.set("status", $("#f-status").value);
  const data = await api("/api/alerts?" + p);
  state.total = data.total;
  $("#alert-rows").replaceChildren(...data.items.map((a) => {
    const tr = el("tr", { class: "clickable" },
      el("td", { text: String(a.id) }), el("td", { text: a.timestamp }),
      el("td", { text: a.source_ip }), el("td", { text: a.signature }),
      el("td", {}, el("span", { class: "badge sev-" + a.severity, text: a.severity })),
      el("td", { text: String(a.score) }), el("td", { text: a.status }));
    tr.addEventListener("click", () => openDetail(a.id));
    return tr;
  }));
  const from = state.total ? state.offset + 1 : 0;
  $("#page-info").textContent = `${from}–${Math.min(state.offset + state.limit, state.total)} von ${state.total}`;
  $("#prev").disabled = state.offset === 0;
  $("#next").disabled = state.offset + state.limit >= state.total;
}
$("#f-apply").addEventListener("click", () => { state.offset = 0; loadAlerts(); });
$("#prev").addEventListener("click", () => { state.offset = Math.max(0, state.offset - state.limit); loadAlerts(); });
$("#next").addEventListener("click", () => { state.offset += state.limit; loadAlerts(); });

async function openDetail(id) {
  const a = await api("/api/alerts/" + id);
  const body = $("#detail-body");
  body.replaceChildren(
    el("h2", { text: `Alert #${a.id}: ${a.signature}` }),
    el("p", { text: `${a.timestamp} | ${a.source_ip} → ${a.dest_ip || "?"} | Score ${a.score}` }),
    el("p", { text: a.mitre_id ? `MITRE ${a.mitre_id}: ${a.mitre_name}` : "Keine MITRE-Zuordnung" }),
    el("pre", { text: a.raw || "(keine Rohdaten)" }));

  const sel = el("select");
  for (const s of ["new", "investigating", "closed", "false_positive"]) {
    const o = el("option", { value: s, text: s }); if (s === a.status) o.selected = true; sel.append(o);
  }
  sel.addEventListener("change", async () => {
    await api("/api/alerts/" + id, { method: "PATCH", body: JSON.stringify({ status: sel.value }) });
    loadAlerts();
  });
  body.append(el("label", {}, "Status", sel), el("h3", { text: "Notizen" }));
  for (const n of a.notes)
    body.append(el("div", { class: "note" }, el("small", { text: `${n.author}, ${n.created_at}` }), el("div", { text: n.text })));

  const input = el("input", { placeholder: "Notiz hinzufügen", maxlength: "2000" });
  const add = el("button", { text: "Speichern" });
  add.addEventListener("click", async () => {
    if (!input.value.trim()) return;
    await api(`/api/alerts/${id}/notes`, { method: "POST", body: JSON.stringify({ text: input.value }) });
    openDetail(id);
  });
  body.append(input, add);

  if (state.role === "admin") {
    const del = el("button", { class: "secondary", text: "Alert löschen" });
    del.addEventListener("click", async () => {
      if (!confirm("Alert wirklich löschen?")) return;
      await api("/api/alerts/" + id, { method: "DELETE" });
      $("#detail").close(); loadAlerts();
    });
    body.append(del);
  }
  if (!$("#detail").open) $("#detail").showModal();
}
$("#detail-close").addEventListener("click", () => $("#detail").close());

// ---------- Neuer Alert ----------
$("#new-alert").addEventListener("click", () => $("#create").showModal());
$("#create-close").addEventListener("click", () => $("#create").close());
$("#create-form").addEventListener("submit", async (e) => {
  e.preventDefault();
  const f = new FormData(e.target);
  const payload = { timestamp: new Date().toISOString(), source_ip: f.get("source_ip"),
    dest_ip: f.get("dest_ip") || null, signature: f.get("signature"), severity: f.get("severity") };
  try {
    await api("/api/alerts", { method: "POST", body: JSON.stringify(payload) });
    e.target.reset(); $("#create-error").textContent = ""; $("#create").close(); loadAlerts();
  } catch (err) { $("#create-error").textContent = err.message; }
});

// ---------- Regeln ----------
async function loadRules() {
  const rules = await api("/api/rules");
  $("#rule-rows").replaceChildren(...rules.map((r) => el("tr", {},
    el("td", { text: r.keyword }), el("td", { text: r.mitre_id }),
    el("td", { text: r.mitre_name }), el("td", { text: String(r.base_score) }))));
}

showApp();
