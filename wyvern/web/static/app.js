"use strict";
const $ = (s) => document.querySelector(s);
const SVGNS = "http://www.w3.org/2000/svg";
const ROLE_ICON = {
  router: "🛰️", printer: "🖨️", camera: "📷", nas: "💽", iot: "🔌",
  phone: "📱", workstation: "💻", server: "🖧", gpu_host: "🧠", unknown: "❔",
};
const LEVELS = { None: 0, Low: 1, Medium: 2, High: 3, Critical: 4 };

function fmtTime(ts) {
  if (!ts) return "";
  const d = new Date(ts * 1000);
  return d.toLocaleTimeString();
}
async function api(path) {
  const r = await fetch(path);
  if (!r.ok) throw new Error(path + " -> " + r.status);
  return r.json();
}
async function post(path, body) {
  const r = await fetch(path, {
    method: "POST", headers: { "Content-Type": "application/json" },
    body: JSON.stringify(body || {}),
  });
  return r.json();
}

function renderStats(s) {
  const cells = [
    ["Devices", s.devices], ["Events", s.events_processed], ["Alerts", s.alerts],
    ["Threat", s.overall_level],
    ["Baseline", s.learning ? Math.round((s.learning_progress || 0) * 100) + "% learning" : "ready"],
  ];
  $("#stats").innerHTML = cells
    .map(([k, v]) => `<div class="stat"><div class="v">${v}</div><div class="k">${k}</div></div>`)
    .join("");
}

function renderBanner(a) {
  const b = $("#banner");
  b.className = "banner level-" + (a.overall_level_label || "None");
  $("#banner-level").textContent = (a.overall_level_label || "Low").toUpperCase();
  $("#banner-summary").textContent = a.summary || "";
  $("#banner-summary").className = "banner-summary";
}

function renderTopology(topo) {
  const svg = $("#topo-svg");
  svg.setAttribute("viewBox", "0 0 800 460");
  while (svg.firstChild) svg.removeChild(svg.firstChild);
  const cx = 400, cy = 230, maxR = 195;
  const nodes = topo.nodes || [];
  const ringFor = (n) => {
    const lvl = LEVELS[n.threat_level] || 0;
    if (n.worm_suspect || lvl >= 4) return 0.16;
    if (lvl === 3) return 0.40;
    if (lvl === 2) return 0.62;
    return 0.86;
  };
  const pos = {};
  nodes.forEach((n, i) => {
    const ang = (i / Math.max(1, nodes.length)) * Math.PI * 2 - Math.PI / 2;
    const r = maxR * ringFor(n) + ((i % 3) - 1) * 10;
    pos[n.id] = { x: cx + r * Math.cos(ang), y: cy + r * Math.sin(ang), n };
  });
  // edges
  (topo.edges || []).forEach((e) => {
    const a = pos[e.src], b = pos[e.dst];
    if (!a || !b) return;
    const ln = document.createElementNS(SVGNS, "line");
    ln.setAttribute("x1", a.x); ln.setAttribute("y1", a.y);
    ln.setAttribute("x2", b.x); ln.setAttribute("y2", b.y);
    ln.setAttribute("class", "link" + (e.worm ? " worm" : ""));
    svg.appendChild(ln);
  });
  // nodes
  const color = (lvl) => ({ None: "#3fb950", Low: "#6ea8fe", Medium: "#e3b341", High: "#f0883e", Critical: "#f85149" }[lvl] || "#3fb950");
  Object.values(pos).forEach(({ x, y, n }) => {
    const g = document.createElementNS(SVGNS, "g");
    g.setAttribute("class", "node" + (n.worm_suspect ? " worm" : ""));
    g.setAttribute("transform", `translate(${x},${y})`);
    const c = document.createElementNS(SVGNS, "circle");
    c.setAttribute("r", 9 + (n.threat_score || 0) / 100 * 9);
    c.setAttribute("fill", color(n.threat_level));
    const title = document.createElementNS(SVGNS, "title");
    title.textContent = `${n.label} (${n.role})\n${n.ip || ""}\nthreat: ${n.threat_level} ${n.threat_score}`;
    c.appendChild(title);
    const icon = document.createElementNS(SVGNS, "text");
    icon.setAttribute("dy", "-14"); icon.textContent = ROLE_ICON[n.role] || "❔";
    const label = document.createElementNS(SVGNS, "text");
    label.setAttribute("dy", "24");
    label.textContent = (n.label || "").slice(0, 16);
    g.appendChild(c); g.appendChild(icon); g.appendChild(label);
    svg.appendChild(g);
  });
  if (!nodes.length) {
    const t = document.createElementNS(SVGNS, "text");
    t.setAttribute("x", cx); t.setAttribute("y", cy); t.setAttribute("text-anchor", "middle");
    t.setAttribute("fill", "#5d6776"); t.textContent = "waiting for traffic…";
    svg.appendChild(t);
  }
}

function alertItem(a) {
  const recs = (a.recommendations || []).slice(0, 3)
    .map((r) => `<li>${escapeHtml(r)}</li>`).join("");
  const stage = a.stage ? `<span class="tag ${a.stage === "worm" ? "worm" : ""}">${escapeHtml(a.stage)}</span>` : "";
  return `<li class="sev-${a.severity}">
    <div class="a-title">${escapeHtml(a.title)}</div>
    <div class="a-meta">
      <span>${fmtTime(a.ts)}</span><span class="tag">${escapeHtml(a.severity_label)}</span>
      <span class="tag">${escapeHtml(a.detector)}</span>${stage}
      <span>conf ${Math.round((a.confidence || 0) * 100)}%</span>
      ${a.src_ip ? `<span>src ${a.src_ip}</span>` : ""}
    </div>
    <div class="a-desc">${escapeHtml(a.description || "")}</div>
    ${recs ? `<ul class="a-recs">${recs}</ul>` : ""}
  </li>`;
}
function renderAlerts(list) {
  $("#alerts").innerHTML = list.map(alertItem).join("");
  $("#alert-count").textContent = list.length ? `${list.length} recent` : "";
}

function renderDevices(list) {
  const rows = list.map((d) => {
    const watchCls = d.suspicious ? "watch on" : "watch";
    const id = d.ip || d.mac;
    return `<tr class="${d.worm_suspect ? "worm" : ""}">
      <td><span class="pill lvl-${d.threat_level}">${d.threat_level}</span></td>
      <td>${ROLE_ICON[d.role] || "❔"} ${escapeHtml(d.label || d.mac)}</td>
      <td>${escapeHtml(d.ip || "")}</td><td>${escapeHtml(d.role)}</td><td>${escapeHtml(d.vendor || "")}</td>
      <td>${escapeHtml(d.os_guess || "")}</td><td>${d.gpu_capable ? "✓" : ""}</td>
      <td>${(d.open_ports || []).slice(0, 6).join(", ")}</td>
      <td><button class="${watchCls}" data-id="${escapeHtml(id)}" data-on="${d.suspicious ? 1 : 0}">
        ${d.suspicious ? "watching" : "watch"}</button></td>
    </tr>`;
  }).join("");
  $("#devices tbody").innerHTML = rows;
  document.querySelectorAll(".watch").forEach((btn) => {
    btn.onclick = async () => {
      const on = btn.dataset.on === "1";
      await post(`/api/devices/${encodeURIComponent(btn.dataset.id)}/suspicious`, { value: !on });
      refreshDevices();
    };
  });
}

function escapeHtml(s) {
  return String(s).replace(/[&<>"']/g, (c) =>
    ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));
}

async function refreshDevices() {
  try { renderDevices(await api("/api/devices")); renderTopology(await api("/api/topology")); }
  catch (e) { /* ignore transient */ }
}
async function refreshAll() {
  try {
    renderStats(await api("/api/stats"));
    renderBanner(await api("/api/assessment"));
    renderAlerts(await api("/api/alerts?limit=100"));
    await refreshDevices();
  } catch (e) { console.warn(e); }
}

function connectStream() {
  let es;
  try { es = new EventSource("/api/stream"); } catch (e) { return; }
  let pending = false;
  const debouncedRefresh = () => {
    if (pending) return; pending = true;
    setTimeout(() => { pending = false; refreshStatsAndDevices(); }, 800);
  };
  es.onmessage = (ev) => {
    let msg; try { msg = JSON.parse(ev.data); } catch { return; }
    if (msg.type === "assessment") renderBanner(msg.assessment);
    else if (msg.type === "alert") { prependAlert(msg.alert); debouncedRefresh(); }
    else if (msg.type === "device_update") debouncedRefresh();
  };
  es.onerror = () => { /* EventSource auto-reconnects */ };
}
async function refreshStatsAndDevices() {
  try { renderStats(await api("/api/stats")); await refreshDevices(); } catch (e) {}
}
function prependAlert(a) {
  const ul = $("#alerts");
  ul.insertAdjacentHTML("afterbegin", alertItem(a));
  while (ul.children.length > 150) ul.removeChild(ul.lastChild);
}

refreshAll();
connectStream();
setInterval(refreshAll, 20000);
