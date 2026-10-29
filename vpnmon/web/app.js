"use strict";

// ---------------------------------------------------------------- helpers
const $ = (sel, root = document) => root.querySelector(sel);
const $$ = (sel, root = document) => [...root.querySelectorAll(sel)];
const esc = (v) => String(v ?? "").replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));
const fmtNum = (n) => Number(n || 0).toLocaleString("ru-RU");
const pad = (n) => String(n).padStart(2, "0");
const fmtTs = (ts, withDate = true) => {
  const d = new Date(ts * 1000);
  const t = `${pad(d.getHours())}:${pad(d.getMinutes())}`;
  return withDate ? `${pad(d.getDate())}.${pad(d.getMonth() + 1)} ${t}` : t;
};
const fmtDate = (ts) => { const d = new Date(ts * 1000); return `${pad(d.getDate())}.${pad(d.getMonth() + 1)}.${d.getFullYear()}`; };
const fmtDur = (sec) => {
  sec = Math.max(0, Math.round(sec));
  const d = Math.floor(sec / 86400), h = Math.floor((sec % 86400) / 3600), m = Math.floor((sec % 3600) / 60);
  if (d) return `${d}д ${h}ч`;
  if (h) return `${h}ч ${pad(m)}м`;
  return `${m}м`;
};
const fmtCount = (n) => {
  n = Number(n || 0);
  if (n >= 1e6) return `${(n / 1e6).toFixed(1)}M`;
  if (n >= 1e4) return `${Math.round(n / 1e3)}k`;
  return fmtNum(n);
};
const ago = (ts) => {
  const s = Math.round(Date.now() / 1000 - ts);
  if (s < 5) return "только что";
  if (s < 60) return `${s} с назад`;
  if (s < 3600) return `${Math.floor(s / 60)} мин назад`;
  return fmtTs(ts);
};
// Cisco ages: "03:21:20", "1d02h", "2w3d"
const parseAge = (txt) => {
  const v = String(txt || "").toLowerCase();
  let m = v.match(/^(\d+):(\d{1,2}):(\d{1,2})$/);
  if (m) return +m[1] * 3600 + +m[2] * 60 + +m[3];
  const units = { y: 31536000, w: 604800, d: 86400, h: 3600, m: 60, s: 1 };
  const parts = [...v.matchAll(/(\d+)([ywdhms])/g)];
  return parts.length ? parts.reduce((a, p) => a + +p[1] * units[p[2]], 0) : null;
};
const versionKey = (v) => String(v || "").split(".").map((x) => x.padStart(6, "0")).join(".");
const EVENT_LABELS = { CONNECTED: "Вход", DISCONNECTED: "Выход", ALERT: "Тревога", ERROR: "Ошибка", ADMIN: "Действие", AUTH: "Доступ", INFO: "Инфо", SNAPSHOT: "Снимок", GAP: "Простой", CONFIG: "Конфигурация" };
const SEVERITY_LABELS = ["emerg", "alert", "crit", "error", "warning", "notice", "info", "debug"];
const isAdmin = () => S.role === "admin";
const STATUS_TEXT = { ok: "работает", error: "нет связи", not_configured: "не настроено", starting: "запуск…", disabled: "отключено" };

async function api(method, path, body) {
  const opts = { method, headers: { "X-Requested-With": "vpnmon" }, credentials: "same-origin" };
  if (body !== undefined) {
    opts.headers["Content-Type"] = "application/json";
    opts.body = JSON.stringify(body);
  }
  const res = await fetch(path, opts);
  const data = res.headers.get("content-type")?.includes("json") ? await res.json() : null;
  if (res.status === 401 && !path.startsWith("/api/auth/")) {
    // Only an expired session in an open panel sends the user back to the login form.
    if (!$("#shell").classList.contains("hidden")) showAuth();
    throw new Error("Требуется вход");
  }
  if (!res.ok) throw new Error(data?.error || `HTTP ${res.status}`);
  return data;
}

let toastTimer;
function toast(msg, bad = false) {
  const t = $("#toast");
  t.textContent = msg;
  t.className = "toast" + (bad ? " bad" : "");
  clearTimeout(toastTimer);
  toastTimer = setTimeout(() => t.classList.add("hidden"), bad ? 6000 : 3000);
}

function modal({ title, html = "", actions = [], wide = false }) {
  return new Promise((resolve) => {
    $("#m-title").textContent = title;
    $("#m-body").innerHTML = html;
    $(".modal-card").classList.toggle("wide", wide);
    const bar = $("#m-actions");
    bar.innerHTML = "";
    const close = (v) => { $("#modal").classList.add("hidden"); resolve(v); };
    for (const a of [...actions, { label: actions.length ? "Отмена" : "Закрыть", value: null }]) {
      const b = document.createElement("button");
      b.type = "button";
      b.className = "btn " + (a.cls || "");
      b.textContent = a.label;
      b.onclick = async () => {
        if (a.onClick) {
          // Keep the dialog open when validation fails.
          b.disabled = true;
          try { if ((await a.onClick()) === false) return; } finally { b.disabled = false; }
        }
        close(a.value === undefined ? true : a.value);
      };
      bar.appendChild(b);
    }
    $("#modal").onclick = (e) => { if (e.target.id === "modal") close(null); };
    $("#modal").classList.remove("hidden");
    ($("#m-body input:not([type=checkbox])") || bar.querySelector(".primary, .solid") || bar.lastChild).focus();
  });
}

async function copyText(text, label) {
  try { await navigator.clipboard.writeText(text); toast(label); }
  catch { modal({ title: "Скопируйте текст", html: `<textarea readonly class="mono">${esc(text)}</textarea>` }); }
}

function sortRows(rows, key, desc) {
  const dir = desc ? -1 : 1;
  return [...rows].sort((a, b) => {
    let x = a[key], y = b[key];
    if (key === "client_version") { x = versionKey(x); y = versionKey(y); }
    if (typeof x === "number" || typeof y === "number") return ((x ?? -1) - (y ?? -1)) * dir;
    return String(x ?? "").localeCompare(String(y ?? ""), "ru", { numeric: true }) * dir;
  });
}

function bindSort(table, state, render) {
  $$("th[data-k]", table).forEach((th) => {
    th.onclick = () => {
      if (state.key === th.dataset.k) state.desc = !state.desc;
      else { state.key = th.dataset.k; state.desc = th.classList.contains("num"); }
      render();
    };
  });
}

function markSorted(table, state) {
  $$("th[data-k]", table).forEach((th) => {
    th.classList.toggle("sorted", th.dataset.k === state.key);
    th.classList.toggle("desc", th.dataset.k === state.key && state.desc);
  });
}

function segValue(id, attr) {
  return $(`#${id} button.on`)?.dataset[attr];
}

function bindSeg(id, onChange) {
  $(`#${id}`).addEventListener("click", (e) => {
    const b = e.target.closest("button");
    if (!b) return;
    $$(`#${id} button`).forEach((x) => x.classList.toggle("on", x === b));
    onChange();
  });
}

function clientLabel(o) {
  if (!o.client_version && !o.client_agent) return `<span class="muted">—</span>`;
  const text = [o.client_os, o.client_version].filter(Boolean).join(" ") || o.client_agent;
  return o.client_outdated
    ? `<span class="tag warn" title="${esc(o.client_agent)} — устаревшая версия">${esc(text)}</span>`
    : `<span title="${esc(o.client_agent)}">${esc(text)}</span>`;
}

// ---------------------------------------------------------------- bar chart
function barChart(el, points, { label, value, tip, highlight, labelAt, gaps = [], bucket = 0 }) {
  const W = el.clientWidth || 600, H = el.clientHeight || 200;
  const padL = 32, padB = 22, padT = 8;
  const max = Math.max(1, ...points.map(value));
  const step = max <= 5 ? 1 : Math.ceil(max / 4);
  const top = Math.ceil(max / step) * step;
  const iw = W - padL, ih = H - padB - padT;
  const bw = Math.min(56, iw / Math.max(1, points.length));
  let svg = `<svg viewBox="0 0 ${W} ${H}" role="img">`;
  for (let v = 0; v <= top; v += step) {
    const y = padT + ih - (v / top) * ih;
    svg += `<line class="grid" x1="${padL}" x2="${W}" y1="${y}" y2="${y}"/><text class="axis" x="${padL - 6}" y="${y + 4}" text-anchor="end">${v}</text>`;
  }
  const labelEvery = Math.max(1, Math.ceil(points.length / Math.max(1, Math.floor(iw / 64))));
  // Hours when the monitor itself was off: shaded, so "nobody online" isn't confused with "no data".
  const inGap = (p) => bucket && gaps.some((g) => g.start < p.ts + bucket && g.end > p.ts);
  if (bucket && gaps.length) {
    points.forEach((p, i) => {
      if (inGap(p)) svg += `<rect class="gap" x="${padL + i * bw}" y="${padT}" width="${bw}" height="${ih}"/>`;
    });
  }
  points.forEach((p, i) => {
    const v = value(p), h = (v / top) * ih;
    const x = padL + i * bw;
    const gap = bw > 6 ? Math.min(4, bw * 0.2) : 0.5;
    svg += `<rect class="bar${highlight && !highlight(p) ? " dim" : ""}" data-i="${i}" x="${x + gap / 2}" y="${padT + ih - h}" width="${Math.max(1, bw - gap)}" height="${Math.max(v ? 2 : 0, h)}" rx="2"/>`;
    if (labelAt ? labelAt(p, i) : i % labelEvery === 0) svg += `<text class="axis" x="${x + bw / 2}" y="${H - 6}" text-anchor="middle">${esc(label(p))}</text>`;
  });
  svg += "</svg><div class=\"tip hidden\"></div>";
  el.innerHTML = svg;
  const tipEl = $(".tip", el);
  $$("rect.bar", el).forEach((r) => {
    r.onmouseenter = () => {
      const p = points[+r.dataset.i];
      tipEl.textContent = tip(p);
      tipEl.style.left = `${(+r.getAttribute("x") + +r.getAttribute("width") / 2) / W * 100}%`;
      tipEl.style.top = `${+r.getAttribute("y") / H * 100}%`;
      tipEl.classList.remove("hidden");
    };
    r.onmouseleave = () => tipEl.classList.add("hidden");
  });
}

// ---------------------------------------------------------------- state
const S = {
  state: null,
  version: -1,
  view: "overview",
  sessSort: { key: "login", desc: false },
  audit: [],
  auditSort: { key: "connects_period", desc: true },
  auditSel: new Set(),
  pollTimer: null,
  routerNames: {},
};
const multiRouter = () => (S.state?.routers?.length || 0) > 1;

const VIEWS = {
  overview: { title: "Обзор", load: loadOverview },
  sessions: { title: "Активные сессии", load: renderSessions },
  audit: { title: "Аудит пользователей", load: loadAudit },
  accounts: { title: "Учётки на удаление", load: loadCleanup },
  events: { title: "Журнал событий", load: loadEvents },
  routerlog: { title: "Журнал роутера", load: loadSyslog },
  settings: { title: "Настройки", load: loadSettings },
};

function route() {
  const name = (location.hash.replace(/^#\//, "") || "overview").split("?")[0];
  S.view = VIEWS[name] ? name : "overview";
  $$(".view").forEach((v) => v.classList.toggle("hidden", v.id !== `view-${S.view}`));
  $$("#nav a").forEach((a) => a.classList.toggle("active", a.dataset.view === S.view));
  $("#view-title").textContent = VIEWS[S.view].title;
  $("#view-sub").textContent = "";
  updateSelBar();
  VIEWS[S.view].load();
}

// ---------------------------------------------------------------- auth
async function showAuth() {
  clearInterval(S.pollTimer);
  const st = await api("GET", "/api/auth/status");
  $("#shell").classList.add("hidden");
  $("#auth").classList.remove("hidden");
  const setup = st.setup_required;
  $("#auth-title").textContent = setup ? "Первый запуск" : "Вход";
  $("#auth-hint").textContent = setup
    ? (st.setup_allowed ? "Задайте пароль для доступа к веб-панели (от 8 символов)." : "Пароль панели ещё не задан. Откройте панель на компьютере, где запущен сервер.")
    : "Введите пароль веб-панели.";
  $("#auth-confirm-wrap").classList.toggle("hidden", !setup);
  $("#auth-login-wrap").classList.toggle("hidden", setup);
  $("#auth-submit").textContent = setup ? "Сохранить и войти" : "Войти";
  $("#auth-submit").disabled = setup && !st.setup_allowed;
  $("#auth-password").autocomplete = setup ? "new-password" : "current-password";
  $("#auth-form").onsubmit = async (e) => {
    e.preventDefault();
    $("#auth-error").textContent = "";
    const password = $("#auth-password").value;
    try {
      if (setup) {
        if (password !== $("#auth-confirm").value) throw new Error("Пароли не совпадают");
        await api("POST", "/api/auth/setup", { password });
      } else {
        await api("POST", "/api/auth/login", { login: $("#auth-login").value.trim(), password });
      }
      $("#auth-password").value = $("#auth-confirm").value = "";
      start();
    } catch (err) {
      $("#auth-error").textContent = err.message;
    }
  };
  $("#auth-password").focus();
}

async function start() {
  $("#auth").classList.add("hidden");
  $("#shell").classList.remove("hidden");
  await pollState();
  route();
  clearInterval(S.pollTimer);
  S.pollTimer = setInterval(pollState, 5000);
}

// ---------------------------------------------------------------- polling
async function pollState() {
  let st;
  try {
    st = await api("GET", "/api/state");
  } catch (err) {
    setCollector("error", "Сервер недоступен");
    return;
  }
  S.routerNames = Object.fromEntries(st.routers.map((r) => [r.id, r.name]));
  for (const s of st.sessions) {
    s.created_s = parseAge(s.created);
    s.last_used_s = parseAge(s.last_used);
    s.packets = (s.rx_packets || 0) + (s.tx_packets || 0);
    s.router_name = S.routerNames[s.router] || s.router;
  }
  const changed = st.version !== S.version;
  S.state = st;
  S.version = st.version;
  if (S.role !== st.user.role) {
    S.role = st.user.role;
    // Viewers get the same panel without controls; the server refuses those actions anyway.
    document.body.classList.toggle("viewer", !isAdmin());
  }
  $("#whoami").textContent = `${st.user.login} · ${isAdmin() ? "администратор" : "только просмотр"}`;

  const active = st.routers.filter((r) => r.status !== "disabled");
  const failing = active.filter((r) => r.status === "error");
  let statusText;
  if (st.status === "ok") statusText = `${active.length > 1 ? `${active.length} устройства` : st.router} · опрос ${ago(st.last_success_ts)}`;
  else if (st.status === "error") statusText = failing.length === 1 ? `Нет связи с ${failing[0].name}` : `Нет связи: ${failing.length} устр.`;
  else if (st.status === "not_configured") statusText = active.length ? "Устройство не настроено" : "Добавьте устройство";
  else statusText = "Запуск…";
  setCollector(st.status, statusText);
  $("#nav-sessions").textContent = st.kpi.sessions;
  $("#last-poll").textContent = st.last_success_ts ? `Данные: ${fmtTs(st.last_success_ts, false)}` : "";

  const banner = $("#banner");
  if (failing.length) {
    banner.className = "banner";
    banner.innerHTML = failing.map((r) => `<div><b>Нет связи с ${esc(r.name)} (${esc(r.host)}).</b> ${esc(r.last_error)}${r.last_success_ts ? ` Последние данные: ${esc(ago(r.last_success_ts))}.` : ""}</div>`).join("");
  } else if (st.status === "not_configured") {
    banner.className = "banner warn";
    banner.innerHTML = `Сбор данных не идёт: добавьте устройство Cisco в <a href="#/settings">настройках</a>.`;
  } else {
    banner.className = "banner hidden";
  }

  if (changed) {
    if (S.view === "sessions") renderSessions();
    if (S.view === "overview") renderOverviewLive();
  }
}

function setCollector(status, text) {
  const el = $("#collector-status");
  el.className = `collector ${status}`;
  $(".txt", el).textContent = text;
}

// ---------------------------------------------------------------- overview
let concDays = 7;
async function loadOverview() {
  renderOverviewLive();
  loadConcurrency();
  loadClients();
  try {
    const events = await api("GET", "/api/events?limit=12");
    $("#recent-events").innerHTML = events.length
      ? events.map((e) => `<li><span class="time">${fmtTs(e.ts, false)}</span><span class="msg"><span class="tag ev-${esc(e.type)}">${esc(EVENT_LABELS[e.type] || e.type)}</span> ${routerTag(e.router)}${esc(shortMsg(e))}</span></li>`).join("")
      : `<li class="muted">Событий пока нет</li>`;
    const alerts = (await api("GET", `/api/events?type=ALERT&limit=200`)).filter((e) => e.ts > Date.now() / 1000 - 86400);
    $("#k-alerts").textContent = alerts.length;
    $("#k-alerts-card").classList.toggle("hot", alerts.length > 0);
    $("#nav-alerts").textContent = alerts.length;
    $("#nav-alerts").classList.toggle("hidden", !alerts.length);
  } catch (err) { toast(err.message, true); }
}

function routerTag(id) {
  return id && multiRouter() ? `<span class="tag muted">${esc(S.routerNames[id] || id)}</span> ` : "";
}

function shortMsg(e) {
  if (e.type === "CONNECTED" || e.type === "DISCONNECTED") return `${e.login} · ${e.ip}`;
  return e.message;
}

function renderOverviewLive() {
  const st = S.state;
  if (!st) return;
  $("#k-sessions").textContent = st.kpi.sessions;
  $("#k-sessions-sub").textContent = `${fmtNum(st.kpi.tunnels)} туннелей · ${st.kpi.ips} IP`;
  $("#k-users").textContent = st.kpi.users;
  const multi = {};
  st.sessions.forEach((s) => (multi[s.login.toLowerCase()] ??= new Set()).add(s.ip));
  const multiCount = Object.values(multi).filter((x) => x.size > 1).length;
  $("#k-users-sub").textContent = multiCount ? `${multiCount} с нескольких IP` : "каждый с одного IP";
  const list = sortRows(st.sessions, "created_s", true);
  $("#online-list").innerHTML = list.length
    ? list.map((s) => `<li><span><span class="live"></span><b>${esc(s.login)}</b></span><span class="muted">${esc(s.country && s.country !== "—" ? s.country.split(" / ")[0] : s.ip)} · ${s.created_s != null ? fmtDur(s.created_s) : esc(s.created)}</span></li>`).join("")
    : `<li class="muted">Никого нет в сети</li>`;
  $("#routers-card").classList.toggle("hidden", !multiRouter());
  $("#router-chips").innerHTML = st.routers.map((r) => `<div class="router-chip ${esc(r.status)}">
      <span class="dot"></span><div><b>${esc(r.name)}</b><small>${esc(r.host)} · ${esc(STATUS_TEXT[r.status] || r.status)}</small></div>
      <span class="count">${r.sessions}</span></div>`).join("");
}

async function loadConcurrency() {
  try {
    const data = await api("GET", `/api/stats/concurrency?days=${concDays}`);
    const pts = data.points;
    const peak = Math.max(0, ...pts.map((p) => p.peak));
    if (concDays === 7) {
      const at = pts.find((p) => p.peak === peak);
      $("#k-peak").textContent = peak;
      $("#k-peak-sub").textContent = at && peak ? `${fmtTs(at.ts)} — ${at.users} польз.` : "нет данных";
    }
    const hourly = data.bucket === 3600;
    const dayLabel = (d) => `${pad(d.getDate())}.${pad(d.getMonth() + 1)}`;
    const everyDays = Math.max(1, Math.ceil(pts.length / 12));
    barChart($("#conc-chart"), pts, {
      value: (p) => p.peak,
      // 24 h: hours; 7 days: one date label per midnight; 30/90 days: every few days.
      label: (p) => {
        const d = new Date(p.ts * 1000);
        return concDays === 1 ? `${pad(d.getHours())}:00` : dayLabel(d);
      },
      labelAt: (p, i) => {
        const h = new Date(p.ts * 1000).getHours();
        if (concDays === 1) return h % 3 === 0;
        return hourly ? h === 0 : i % everyDays === 0;
      },
      tip: (p) => `${hourly ? fmtTs(p.ts) : dayLabel(new Date(p.ts * 1000))} — пик ${p.peak} сесс., ${p.users} польз.`
        + (data.gaps.some((g) => g.start < p.ts + data.bucket && g.end > p.ts) ? " (монитор не работал — данные неполные)" : ""),
      highlight: (p) => { const h = new Date(p.ts * 1000).getHours(); return !hourly || (h >= 8 && h < 20); },
      gaps: data.gaps,
      bucket: data.bucket,
    });
    const down = data.gaps.reduce((a, g) => a + g.end - g.start, 0);
    $("#conc-note").textContent = down
      ? `Серым отмечено время, когда монитор не работал (${fmtDur(down)} за период): входы и выходы в эти часы могли не попасть в статистику.`
      : "";
  } catch (err) { toast(err.message, true); }
}

async function loadClients() {
  try {
    const d = await api("GET", "/api/clients?days=90");
    const outdated = d.groups.filter((g) => g.outdated).reduce((a, g) => a + g.users.length, 0);
    $("#clients-sub").textContent = d.users_with_data
      ? `${d.users_with_data} польз. с известной версией${d.min_version ? ` · минимальная ${d.min_version}${outdated ? `, устаревших: ${outdated}` : ""}` : ""}`
      : "";
    const max = Math.max(1, ...d.groups.map((g) => g.users.length));
    $("#clients-list").innerHTML = d.groups.length
      ? d.groups.map((g) => `<div class="client-row ${g.outdated ? "old" : ""}">
          <span class="client-name">${esc(g.os)} <b>${esc(g.version)}</b>${g.outdated ? ` <span class="tag warn">устарел</span>` : ""}</span>
          <span class="client-bar"><i style-width="${Math.round(g.users.length / max * 100)}"></i></span>
          <span class="client-count" title="${esc(g.users.join(", "))}">${g.users.length}</span></div>`).join("")
      : `<p class="muted">Данные о клиентах появятся после следующих подключений (собираются из подробностей сессий).</p>`;
    // CSP forbids inline style attributes; widths are set through the CSSOM instead.
    $$("#clients-list [style-width]").forEach((i) => { i.style.width = `${i.getAttribute("style-width")}%`; });
  } catch (err) { toast(err.message, true); }
}

// ---------------------------------------------------------------- sessions
function renderRouterFilter() {
  const seg = $("#s-router");
  const multi = multiRouter();
  seg.classList.toggle("hidden", !multi);
  $$(".col-router").forEach((c) => c.classList.toggle("hidden", !multi));
  if (!multi) return;
  const current = segValue("s-router", "r") ?? "";
  const ids = S.state.routers.map((r) => r.id);
  if (seg.dataset.ids !== ids.join(",")) {
    seg.dataset.ids = ids.join(",");
    seg.innerHTML = `<button data-r="" class="${current === "" ? "on" : ""}">Все</button>` + S.state.routers.map((r) =>
      `<button data-r="${esc(r.id)}" class="${current === r.id ? "on" : ""}">${esc(r.name)}</button>`).join("");
  }
}

function renderSessions() {
  const st = S.state;
  if (!st) return;
  renderRouterFilter();
  const multi = multiRouter();
  const routerFilter = multi ? segValue("s-router", "r") || "" : "";
  const q = $("#s-search").value.trim().toLowerCase();
  const ipsByLogin = {};
  st.sessions.forEach((s) => (ipsByLogin[s.login.toLowerCase()] ??= new Set()).add(s.ip));
  let rows = st.sessions.filter((s) => (!routerFilter || s.router === routerFilter) &&
    (!q || [s.login, s.ip, s.country, s.org, s.context, s.client_agent, s.router_name].join(" ").toLowerCase().includes(q)));
  rows = sortRows(rows, S.sessSort.key, S.sessSort.desc);
  markSorted($("#s-table"), S.sessSort);
  $("#s-count").textContent = rows.length !== st.sessions.length ? `${rows.length} из ${st.sessions.length}` : `${st.sessions.length} сессий`;
  $("#s-empty").classList.toggle("hidden", rows.length > 0);
  $("#s-table tbody").innerHTML = rows.map((s) => {
    const multiIp = ipsByLogin[s.login.toLowerCase()].size > 1;
    const idle = s.last_used_s ?? 0;
    return `<tr class="${multiIp ? "warnrow" : ""}" data-i="${st.sessions.indexOf(s)}">
      <td><span class="live"></span><a href="#" class="login link" data-user="${esc(s.login)}">${esc(s.login)}</a>${multiIp ? ` <span class="tag warn" title="Одновременно с нескольких IP">${ipsByLogin[s.login.toLowerCase()].size} IP</span>` : ""}</td>
      <td class="col-router ${multi ? "" : "hidden"}">${esc(s.router_name)}</td>
      <td class="mono" title="${s.tunnel_ip ? `IP в туннеле: ${esc(s.tunnel_ip)}` : ""}">${esc(s.ip)}</td>
      <td>${esc(s.country)}</td>
      <td class="ellipsis" title="${esc(s.org)}">${esc(s.org)}</td>
      <td>${clientLabel(s)}</td>
      <td class="num" title="Принято ${fmtNum(s.rx_packets)} / отправлено ${fmtNum(s.tx_packets)} пакетов">${s.packets ? `${fmtCount(s.rx_packets)} / ${fmtCount(s.tx_packets)}` : `<span class="muted">—</span>`}</td>
      <td class="num">${s.connections}</td>
      <td class="num" title="${esc(s.created)}">${s.created_s != null ? fmtDur(s.created_s) : esc(s.created)}</td>
      <td class="num ${idle > 1800 ? "muted" : ""}" title="${esc(s.last_used)}">${s.last_used_s != null ? fmtDur(s.last_used_s) : esc(s.last_used)}</td>
      <td class="actions"><button class="icon-btn" data-act="details" title="Подробности с устройства">ⓘ</button>${isAdmin() ? `<button class="icon-btn danger" data-act="disconnect" title="Отключить сессию">✕</button>` : ""}</td>
    </tr>`;
  }).join("");
}

async function sessionAction(act, s) {
  const id = { router: s.router, context: s.context, login: s.login, ip: s.ip };
  if (act === "details") {
    modal({ title: `Сессия ${s.login}`, html: `<p class="muted">Запрос к устройству…</p>`, wide: true });
    try {
      const d = await api("POST", "/api/sessions/details", id);
      $("#m-body").innerHTML = `<p class="muted small"><code>${esc(d.command)}</code></p><pre>${esc(d.output.trim())}</pre>`;
    } catch (err) {
      $("#m-body").innerHTML = `<p class="error-text">${esc(err.message)}</p>`;
    }
    return;
  }
  const ok = await modal({
    title: "Отключить сессию?",
    html: `<p>Пользователь <b>${esc(s.login)}</b> с IP <code>${esc(s.ip)}</code> (${multiRouter() ? `${esc(s.router_name)}, ` : ""}контекст ${esc(s.context)}) будет отключён от VPN.</p><p class="muted small">Пользователь сможет переподключиться, если его учётная запись не заблокирована.</p>`,
    actions: [{ label: "Отключить", cls: "danger solid", value: true }],
  });
  if (!ok) return;
  try {
    const r = await api("POST", "/api/sessions/disconnect", id);
    toast(`Сессия ${s.login} отключена: ${r.command}`);
    setTimeout(pollState, 2500);
  } catch (err) {
    modal({ title: "Не удалось отключить", html: `<pre>${esc(err.message)}</pre>` });
  }
}

// ---------------------------------------------------------------- audit
async function loadAudit() {
  const days = segValue("a-period", "days");
  $("#a-export").href = `/api/export/audit.csv?days=${days}`;
  try {
    [S.audit, S.auditDowntime] = await Promise.all([
      api("GET", `/api/audit?days=${days}`), api("GET", `/api/downtime?days=${days}`),
    ]);
  } catch (err) { toast(err.message, true); return; }
  renderAudit();
}

function renderAudit() {
  const f = segValue("a-filter", "f");
  const q = $("#a-search").value.trim().toLowerCase();
  const counts = { all: S.audit.length, active: 0, inactive: 0, online: 0, unstable: 0, outdated: 0 };
  S.audit.forEach((u) => {
    counts[u.status === "ACTIVE" ? "active" : "inactive"]++;
    if (u.online) counts.online++;
    if (u.unstable) counts.unstable++;
    if (u.client_outdated) counts.outdated++;
  });
  for (const k in counts) $(`#a-c-${k}`).textContent = counts[k];
  const match = {
    all: () => true,
    active: (u) => u.status === "ACTIVE",
    inactive: (u) => u.status !== "ACTIVE",
    online: (u) => u.online,
    unstable: (u) => u.unstable,
    outdated: (u) => u.client_outdated,
  }[f] || (() => true);
  let rows = S.audit.filter((u) => match(u) && (!q || u.login.toLowerCase().includes(q)));
  rows = sortRows(rows, S.auditSort.key, S.auditSort.desc);
  markSorted($("#a-table"), S.auditSort);
  const days = segValue("a-period", "days");
  const down = S.auditDowntime?.total_seconds || 0;
  $("#view-sub").textContent = `Период: ${days} дн. · активных ${counts.active}, неактивных ${counts.inactive}`
    + (down ? ` · монитор не работал ${fmtDur(down)} (${S.auditDowntime.count} раз) — данные за эти часы неполные` : "");
  $("#a-table tbody").innerHTML = rows.map((u) => {
    const status = u.online ? `<span class="tag good"><span class="live"></span>В сети</span>`
      : u.status === "ACTIVE" ? `<span class="tag good">Активен</span>` : `<span class="tag bad">Неактивен</span>`;
    return `<tr class="click ${S.auditSel.has(u.login) ? "selected" : ""}" data-user="${esc(u.login)}">
      <td class="chk"><input type="checkbox" data-sel="${esc(u.login)}" ${S.auditSel.has(u.login) ? "checked" : ""} aria-label="Выбрать ${esc(u.login)}"></td>
      <td>${status}</td>
      <td class="login">${esc(u.login)}${u.source === "imported" ? ` <span class="tag muted">импорт</span>` : ""}</td>
      <td class="num">${u.connects_period}</td>
      <td class="num">${u.active_days}</td>
      <td class="num">${esc(u.work_time)}</td>
      <td class="num">${u.unique_ips}</td>
      <td class="num">${reconnectCell(u)}</td>
      <td>${clientLabel(u)}</td>
      <td>${esc(u.last_connected)}</td>
      <td class="num ${u.days_idle >= 30 ? "muted" : ""}">${esc(u.days_idle_str)}</td>
      <td class="ellipsis" title="${esc(u.last_org)}">${esc(u.last_country)}</td>
    </tr>`;
  }).join("");
  $("#a-all").checked = rows.length > 0 && rows.every((u) => S.auditSel.has(u.login));
  updateSelBar();
}

function reconnectCell(u) {
  if (!u.reconnects) return `<span class="muted">0</span>`;
  const title = `Всего за период: ${u.reconnects}. Больше всего за день: ${u.reconnects_peak_day} (${u.reconnects_peak_date})`;
  return u.unstable
    ? `<span class="tag warn" title="${esc(title)}">${u.reconnects_peak_day}/день</span>`
    : `<span title="${esc(title)}">${u.reconnects}</span>`;
}

function updateSelBar() {
  const n = S.auditSel.size;
  $("#a-selbar").classList.toggle("hidden", !n || S.view !== "audit");
  $("#a-selcount").textContent = `Выбрано: ${n}`;
}

async function openUser(login) {
  const dr = $("#drawer");
  $("#d-login").textContent = login;
  $("#d-sub").textContent = "Загрузка…";
  $("#d-kpis").innerHTML = "";
  $("#d-history").innerHTML = "";
  $("#d-monthly").innerHTML = "";
  dr.classList.remove("hidden");
  dr.setAttribute("aria-hidden", "false");
  try {
    const d = await api("GET", `/api/users/${encodeURIComponent(login)}?days=90`);
    const h = d.history;
    const total = h.reduce((a, r) => a + r.duration_seconds, 0);
    const ips = new Set(h.map((r) => r.ip));
    const online = h.some((r) => r.is_active);
    const reconnects = h.filter((r) => r.reconnect).length;
    const lastClient = h.find((r) => r.client_agent);
    const sub = [online ? "Сейчас в сети" : h.length ? `Последний вход: ${h[0].first_seen_iso}` : "Входов за 90 дней нет"];
    if (lastClient) sub.push(`клиент: ${lastClient.client_agent}`);
    $("#d-sub").textContent = sub.join(" · ");
    $("#d-kpis").innerHTML = [
      ["Сессий", h.length], ["Время в сети", fmtDur(total)], ["Разных IP", ips.size], ["Переподключений", reconnects],
    ].map(([k, v]) => `<div><span>${k}</span><b>${esc(v)}</b></div>`).join("");
    const monthly = [...d.monthly].reverse();
    if (monthly.length) {
      barChart($("#d-monthly"), monthly, {
        value: (m) => m[1], label: (m) => m[0], tip: (m) => `${m[0]}: ${m[1]} сесс.`,
      });
    } else $("#d-monthly").innerHTML = `<p class="muted">Нет данных</p>`;
    $("#d-history").innerHTML = h.map((r) => `<tr class="${r.reconnect ? "reconnect" : ""}">
      <td>${esc(r.first_seen_iso.slice(0, 16))}${r.reconnect ? ` <span class="tag warn" title="Через ${esc(fmtDur(Math.max(0, r.gap_seconds)))} после предыдущей сессии">↻</span>` : ""}</td>
      <td>${r.is_active ? `<span class="tag good"><span class="live"></span>в сети</span>` : esc(r.last_seen_iso.slice(5, 16))}</td>
      <td class="num">${esc(fmtDur(r.duration_seconds))}</td>
      <td class="mono">${esc(r.ip)}</td>
      <td class="ellipsis" title="${esc(r.org)}">${multiRouter() ? `${esc(S.routerNames[r.router] || r.router)} · ` : ""}${esc(r.country || "—")}</td>
      <td>${r.client_version ? esc(`${r.client_os} ${r.client_version}`) : `<span class="muted">—</span>`}</td></tr>`).join("") || `<tr><td colspan="6" class="muted">Нет сессий</td></tr>`;
  } catch (err) {
    $("#d-sub").textContent = err.message;
  }
}

function closeDrawer() {
  $("#drawer").classList.add("hidden");
  $("#drawer").setAttribute("aria-hidden", "true");
}

// ---------------------------------------------------------------- accounts cleanup
async function loadCleanup(days) {
  try {
    if (isAdmin()) {
      const settings = await api("GET", "/api/settings");
      if (!$("#c-days").value) $("#c-days").value = settings.cleanup_idle_days;
      $("#c-exclude").value = (settings.cleanup_exclude || []).join(" ");
    }
    const d = await api("GET", `/api/cleanup?days=${encodeURIComponent(days || $("#c-days").value)}`);
    renderCleanup(d);
  } catch (err) { toast(err.message, true); }
}

function renderCleanup(d) {
  const total = d.routers.reduce((a, r) => a + r.candidates.length, 0);
  $("#view-sub").textContent = `Без входа ${d.idle_days}+ дней · кандидатов: ${total}`;
  $("#c-routers").innerHTML = d.routers.map((r, i) => {
    const notSynced = !r.synced_ts;
    let note;
    if (notSynced) note = `Список учёток с этого устройства ещё не загружен — нажмите «Обновить список учёток с роутеров».`;
    else if (!r.observed_since) note = "Сессий с этого устройства пока нет — не с чем сравнивать.";
    else note = `Учёток в конфиге: ${r.users_total}, загружено ${fmtTs(r.synced_ts)}. Наблюдение за входами ведётся с ${fmtDate(r.observed_since)} (${r.observed_days} дн.)`
      + (r.observed_days < d.idle_days ? ` — <b>учётки без единого входа появятся в списке не раньше ${esc(r.ready_from)}</b>: раньше нельзя отличить неиспользуемую учётку от сотрудника в отпуске.` : ".");
    const rows = r.candidates.map((c) => `<tr><td class="login">${esc(c.login)}</td>
      <td>${c.never ? `<span class="muted">не входил с начала наблюдения</span>` : esc(c.last_activity)}</td>
      <td class="num">${c.idle_days}</td></tr>`).join("");
    return `<div class="card cleanup-card">
      <div class="card-head"><h2>${esc(r.name)} <span class="muted small">${esc(r.host)}</span></h2>
        <span class="tag ${r.candidates.length ? "warn" : "good"}">${r.candidates.length ? `${r.candidates.length} к удалению` : "нечего удалять"}</span></div>
      <p class="muted small">${note}</p>
      ${r.candidates.length ? `<div class="grid-2 cleanup-grid">
        <div class="table-wrap static"><table class="table dense"><thead><tr><th>Учётка</th><th>Последний вход</th><th class="num">Дней без входа</th></tr></thead><tbody>${rows}</tbody></table></div>
        <div><div class="card-head"><h3>Команды для роутера</h3><button class="btn sm" type="button" data-copy="${i}">Копировать</button></div>
        <pre class="commands" id="c-cmd-${i}">${esc(r.commands)}</pre>
        <p class="muted small">Выполните в SSH-сессии на устройстве. Пустая строка после команды отвечает на вопрос IOS <code>[confirm]</code>. Сначала проверьте, что учётки не используются для чего-то кроме VPN.</p></div>
      </div>` : ""}
      ${r.excluded.length ? `<p class="muted small">Не предлагаются к удалению: ${r.excluded.map((x) => `${esc(x.login)} (${esc(x.reason)})`).join(", ")}. Сейчас активны или недавно входили: ${r.active}.</p>` : ""}
    </div>`;
  }).join("") || `<div class="card"><p class="muted">Нет настроенных устройств.</p></div>`;
  $$("[data-copy]").forEach((b) => b.onclick = () => copyText(d.routers[+b.dataset.copy].commands, "Команды скопированы"));
}

// ---------------------------------------------------------------- events
let eventsTimer;
async function loadEvents() {
  const type = segValue("e-type", "t");
  const q = $("#e-search").value.trim();
  try {
    const rows = await api("GET", `/api/events?limit=1000&type=${encodeURIComponent(type)}&q=${encodeURIComponent(q)}`);
    $("#e-empty").classList.toggle("hidden", rows.length > 0);
    $("#e-list").innerHTML = rows.map((e) => `<li>
      <span class="time">${esc(e.iso)}</span>
      <span><span class="tag ev-${esc(e.type)}">${esc(EVENT_LABELS[e.type] || e.type)}</span></span>
      <span class="msg">${routerTag(e.router)}${esc(e.message)}</span></li>`).join("");
  } catch (err) { toast(err.message, true); }
}

// ---------------------------------------------------------------- settings
async function loadSettings() {
  if (!isAdmin()) return; // a viewer only sees the password card
  try {
    const s = await api("GET", "/api/settings");
    const form = $("#settings-form");
    const wd = $("#weekday-select");
    if (!wd.options.length) wd.innerHTML = s.weekdays.map((d, i) => `<option value="${i}">${esc(d)}</option>`).join("");
    for (const el of form.elements) {
      if (!el.name || !(el.name in s)) continue;
      if (el.type === "checkbox") el.checked = !!s[el.name];
      else el.value = Array.isArray(s[el.name]) ? s[el.name].join(" ") : (s[el.name] ?? "");
    }
    form.telegram_token.placeholder = s.telegram_token_set ? "сохранён — не менять" : "не задан";
    renderBackups(s.backups || []);
    loadRouters();
    loadWebUsers();
    loadServerInfo();
    const rep = await api("GET", "/api/report/preview");
    $("#report-last").textContent = rep.last_sent_ts ? `Последний отчёт отправлен ${fmtTs(rep.last_sent_ts)}.` : "Отчёт ещё не отправлялся.";
  } catch (err) { toast(err.message, true); }
}

async function loadServerInfo() {
  try {
    const info = await api("GET", "/api/server/info");
    $("#server-info").innerHTML = `Версия ${esc(info.version)} на компьютере <b>${esc(info.hostname)}</b>, часовой пояс сервера ${esc(info.timezone)}. `
      + `Данные: <code>${esc(info.data_dir)}</code>. Сбор идёт, пока запущен сервер — закрытие этой вкладки на него не влияет.`;
    const parts = [`<p class="small">Панель открывается по адресу: ${info.urls.map((u) => `<code>${esc(u)}</code>`).join(", ")}</p>`];
    if (info.running.web_bind === "0.0.0.0" && !info.running.web_https) {
      parts.push(`<p class="small warn-text">Панель доступна из сети без шифрования: пароль и данные идут открытым текстом. Включите HTTPS.</p>`);
    }
    if (info.certificate?.sha256) {
      parts.push(`<p class="small">Сертификат самоподписанный, браузер покажет предупреждение — это ожидаемо. Чтобы убедиться, что это ваш сервер, сверьте отпечаток SHA-256:<br><code class="fp">${esc(info.certificate.sha256)}</code><br>Действует до ${esc(info.certificate.valid_until)}.</p>`);
    }
    if (info.running.web_bind === "0.0.0.0") {
      parts.push(`<p class="small muted">Если с других компьютеров не открывается — разрешите порт ${info.running.web_port} во входящих правилах брандмауэра Windows.</p>`);
    }
    if (info.restart_required) {
      parts.push(`<p class="small warn-text">Сохранённые настройки доступа вступят в силу после перезапуска сервера.</p>`);
    }
    $("#access-info").innerHTML = parts.join("");
    $("#restart").classList.toggle("hidden", !info.restart_required);
  } catch (err) { toast(err.message, true); }
}

function renderBackups(list) {
  const kb = (n) => n >= 1048576 ? `${(n / 1048576).toFixed(1)} МБ` : `${Math.max(1, Math.round(n / 1024))} КБ`;
  $("#backup-list").innerHTML = list.length
    ? list.map((b) => `<li><span class="mono">${esc(b.name)}</span><span class="muted">${kb(b.size)} · ${fmtTs(b.mtime)}</span></li>`).join("")
    : `<li class="muted">Копий пока нет — первая появится в течение минуты после запуска сервера</li>`;
}

async function saveSettings(e) {
  e.preventDefault();
  const form = e.target;
  const body = {};
  for (const el of form.elements) {
    if (!el.name) continue;
    if (el.type === "checkbox") body[el.name] = el.checked;
    else if (el.type === "number") body[el.name] = el.value === "" ? undefined : Number(el.value);
    else if (el.type === "password") { if (el.value) body[el.name] = el.value; }
    else if (el.tagName === "SELECT" && el.name === "weekly_report_weekday") body[el.name] = Number(el.value);
    else body[el.name] = el.value;
  }
  try {
    await api("POST", "/api/settings", body);
    form.telegram_token.value = "";
    $("#settings-msg").textContent = `Сохранено в ${fmtTs(Date.now() / 1000, false)}`;
    toast("Настройки сохранены");
    loadSettings();
    setTimeout(pollState, 3000);
  } catch (err) { toast(err.message, true); }
}

// ---------------------------------------------------------------- routers
let routersCache = [];
async function loadRouters() {
  try {
    routersCache = await api("GET", "/api/routers");
    $("#r-table tbody").innerHTML = routersCache.map((r) => {
      const st = r.state || {};
      const status = r.enabled ? (st.status || "starting") : "disabled";
      return `<tr>
        <td><b>${esc(r.name)}</b>${r.id === "main" ? ` <span class="tag muted">основное</span>` : ""}</td>
        <td class="mono">${esc(r.host)}:${r.port}</td>
        <td>${esc(r.username)}</td>
        <td><span class="status-dot ${esc(status)}"></span>${esc(STATUS_TEXT[status] || status)}${st.last_error ? `<div class="muted small ellipsis" title="${esc(st.last_error)}">${esc(st.last_error)}</div>` : ""}${versionNote(st.version)}${skewNote(st.clock_skew_seconds)}</td>
        <td class="num">${st.sessions ?? "—"}</td>
        <td class="actions"><button class="btn sm" data-edit="${esc(r.id)}" type="button">Изменить</button><button class="icon-btn danger" data-del="${esc(r.id)}" type="button" title="Удалить устройство">✕</button></td>
      </tr>`;
    }).join("") || `<tr><td colspan="6" class="muted">Устройств пока нет — добавьте первое.</td></tr>`;
  } catch (err) { toast(err.message, true); }
}

function versionNote(v) {
  if (!v || !v.uptime_seconds) return "";
  const parts = [v.model, v.ios_version && `IOS ${v.ios_version}`].filter(Boolean).join(", ");
  return `<div class="muted small">${esc(parts)} · работает ${esc(fmtDur(v.uptime_seconds))} (с ${esc(fmtTs(v.boot_ts))})${v.reload_reason ? `, причина последней перезагрузки: ${esc(v.reload_reason)}` : ""}</div>`;
}

function skewNote(skew) {
  // Up to 5 minutes is normal: poll timing plus rounding of the session age.
  if (skew == null || Math.abs(skew) < 300) return "";
  const hours = Math.round(Math.abs(skew) / 3600);
  const hint = hours >= 1 && Math.abs(Math.abs(skew) - hours * 3600) < 600
    ? ` — похоже на разные часовые пояса (${hours} ч): проверьте часовой пояс сервера`
    : " — проверьте NTP на роутере и сервере";
  return `<div class="small warn-text">Часы роутера ${skew > 0 ? "спешат" : "отстают"} на ${esc(fmtDur(Math.abs(skew)))}${hint}</div>`;
}

function routerForm(r) {
  return `<div class="form-grid">
    <label>Название<input id="rf-name" value="${esc(r.name || "")}" placeholder="например: Офис Алматы"></label>
    <label>Адрес (IP или имя)<input id="rf-host" value="${esc(r.host || "")}" required></label>
    <label>SSH-порт<input id="rf-port" type="number" min="1" max="65535" value="${esc(r.port || 22)}"></label>
    <label>SSH-логин<input id="rf-username" value="${esc(r.username || "")}" autocomplete="off"></label>
    <label>Пароль<input id="rf-password" type="password" autocomplete="new-password" placeholder="${r.password_set ? "сохранён — не менять" : ""}"></label>
    <label class="switch inline-switch"><input type="checkbox" id="rf-enabled" ${r.enabled !== false ? "checked" : ""}><span></span>Опрашивать</label>
  </div>
  <label>Команда отключения сессии<input id="rf-disconnect" class="mono" value="${esc(r.disconnect_command || "")}" placeholder="webvpn session disconnect context {context} name {login}"></label>
  <p class="muted small">Подстановки: <code>{context}</code>, <code>{login}</code>, <code>{ip}</code>. Несколько вариантов — через <code>;</code>. Пусто — стандартная команда.</p>
  <p class="small" id="rf-result"></p>`;
}

function routerPayload(id) {
  return {
    id, name: $("#rf-name").value, host: $("#rf-host").value, port: Number($("#rf-port").value || 22),
    username: $("#rf-username").value, password: $("#rf-password").value,
    enabled: $("#rf-enabled").checked, disconnect_command: $("#rf-disconnect").value,
  };
}

async function editRouter(r = {}) {
  const isNew = !r.id;
  const result = (text, bad) => { const el = $("#rf-result"); el.textContent = text; el.className = `small ${bad ? "error-text" : "ok-text"}`; };
  const saved = await modal({
    title: isNew ? "Новое устройство" : `Устройство «${r.name}»`,
    html: routerForm(r),
    wide: true,
    actions: [
      { label: "Проверить подключение", cls: "", onClick: async () => {
        result("Подключение…");
        try { const t = await api("POST", "/api/routers/test", routerPayload(r.id)); result(`Подключение работает, активных сессий: ${t.sessions}.`); }
        catch (err) { result(err.message, true); }
        return false;
      } },
      { label: "Сохранить", cls: "primary", onClick: async () => {
        try { await api("POST", "/api/routers/save", routerPayload(r.id)); return true; }
        catch (err) { result(err.message, true); return false; }
      } },
    ],
  });
  if (saved) {
    toast("Устройство сохранено, опрос запущен");
    loadRouters();
    setTimeout(pollState, 3000);
  }
}

async function deleteRouter(r) {
  const ok = await modal({
    title: `Удалить «${r.name}»?`,
    html: `<p>Опрос <code>${esc(r.host)}</code> прекратится. История сессий с этого устройства останется в базе и в аудите.</p>`,
    actions: [{ label: "Удалить", cls: "danger solid", value: true }],
  });
  if (!ok) return;
  try { await api("POST", "/api/routers/delete", { id: r.id }); toast("Устройство удалено"); loadRouters(); pollState(); }
  catch (err) { toast(err.message, true); }
}

// ---------------------------------------------------------------- panel users
let webUsersCache = [];
async function loadWebUsers() {
  try {
    webUsersCache = await api("GET", "/api/web-users");
    $("#u-table tbody").innerHTML = webUsersCache.map((u) => `<tr>
      <td><b>${esc(u.login)}</b>${u.builtin ? ` <span class="tag muted">встроенный</span>` : ""}</td>
      <td>${u.role === "admin" ? `<span class="tag warn">администратор</span>` : `<span class="tag muted">только просмотр</span>`}</td>
      <td class="actions">${u.builtin ? "" : `<button class="btn sm" data-uedit="${esc(u.login)}" type="button">Изменить</button><button class="icon-btn danger" data-udel="${esc(u.login)}" type="button" title="Удалить">✕</button>`}</td>
    </tr>`).join("");
  } catch (err) { toast(err.message, true); }
}

async function editWebUser(u = {}) {
  const isNew = !u.login;
  const result = (text) => { const el = $("#uf-result"); el.textContent = text; el.className = "small error-text"; };
  const dialog = modal({
    title: isNew ? "Новый пользователь панели" : `Пользователь ${u.login}`,
    html: `<div class="form-grid">
      <label>Логин<input id="uf-login" value="${esc(u.login || "")}" ${isNew ? "" : "readonly"} autocomplete="off"></label>
      <label>Роль<select id="uf-role"><option value="viewer">Только просмотр</option><option value="admin">Администратор</option></select></label>
      <label>Пароль${isNew ? " (от 8 символов)" : ""}<input id="uf-password" type="password" autocomplete="new-password" placeholder="${isNew ? "" : "не менять"}"></label>
    </div><p class="small" id="uf-result"></p>`,
    actions: [{ label: "Сохранить", cls: "primary", onClick: async () => {
      try {
        await api("POST", "/api/web-users/save", { login: $("#uf-login").value.trim(), role: $("#uf-role").value, password: $("#uf-password").value });
        return true;
      } catch (err) { result(err.message); return false; }
    } }],
  });
  $("#uf-role").value = u.role || "viewer";
  if (await dialog) { toast("Пользователь сохранён"); loadWebUsers(); }
}

// ---------------------------------------------------------------- router syslog
let syslogTimer;
async function loadSyslog() {
  const kind = segValue("sl-kind", "k") || "";
  const sev = segValue("sl-sev", "s") || "7";
  const q = $("#sl-search").value.trim();
  const code = S.syslogCode || "";
  try {
    const [rows, sum] = await Promise.all([
      api("GET", `/api/syslog?limit=1000&kind=${encodeURIComponent(kind)}&severity=${sev}&q=${encodeURIComponent(q)}&code=${encodeURIComponent(code)}&noise=${$("#sl-noise").checked ? 1 : 0}`),
      api("GET", "/api/syslog/summary"),
    ]);
    renderSyslogStatus(sum);
    $("#sl-codes").innerHTML = sum.codes.length
      ? `<span class="muted small">За 24 ч:</span> ` + sum.codes.slice(0, 14).map((c) => `<button type="button" class="chip sev-${c.severity} ${code === c.code ? "on" : ""}" data-code="${esc(c.code)}">${esc(c.code)} <b>${c.cnt}</b></button>`).join("")
        + (code ? ` <button type="button" class="chip" data-code="">✕ сбросить</button>` : "")
      : "";
    $("#sl-empty").classList.toggle("hidden", rows.length > 0);
    $("#sl-list").innerHTML = rows.map((m) => `<li>
      <span class="time">${esc(m.iso)}</span>
      <span><span class="tag sev-tag sev-${m.severity}">${esc(SEVERITY_LABELS[m.severity] || m.severity)}</span></span>
      <span class="msg"><code class="code">${esc(m.code || "—")}</code> ${routerTag(m.router)}${m.router ? "" : `<span class="tag muted">${esc(m.source_ip)}</span> `}${esc(m.text)}</span></li>`).join("");
  } catch (err) { toast(err.message, true); }
}

function renderSyslogStatus(sum) {
  const r = sum.receiver;
  const serverIp = sum.server_ips.find((a) => a.startsWith("10.")) || sum.server_ips[0] || "<IP сервера>";
  let html;
  if (!r.enabled) {
    html = `<p><b>Приём журнала роутера выключен.</b> ${isAdmin() ? `Включите его в <a href="#/settings" class="link">настройках</a> и перезапустите сервер.` : ""}</p>`;
  } else if (r.error) {
    html = `<p class="error-text"><b>Приём не работает:</b> ${esc(r.error)}</p>`;
  } else if (!sum.sources.length) {
    html = `<p><b>Сервер слушает UDP ${r.port}, но сообщений от роутера ещё не было.</b> Чтобы роутер отправлял журнал и сюда (текущий адрес <code>logging host</code> останется), выполните на нём:</p>
      <pre class="commands">configure terminal
 logging host ${esc(serverIp)}
end
write memory</pre>
      <p class="muted small">На сервере должен быть открыт входящий UDP ${r.port} — его открывает Install-Server.ps1 начиная с версии 4.3.</p>`;
  } else {
    html = `<p class="small"><span class="status-dot ok"></span>Приём идёт на UDP ${r.port}. ` + sum.sources.map((s) =>
      `${esc(s.router ? (S.routerNames[s.router] || s.router) : s.source_ip)}: последнее сообщение ${esc(ago(s.last_ts))}, всего ${fmtNum(s.cnt)}`).join("; ") + `.</p>`;
  }
  $("#sl-status").innerHTML = html;
}

// ---------------------------------------------------------------- wiring
function wire() {
  window.addEventListener("hashchange", route);

  $("#refresh-btn").onclick = async () => {
    try { await api("POST", "/api/refresh"); toast("Опрос устройств запущен"); setTimeout(pollState, 2500); setTimeout(() => VIEWS[S.view].load(), 3500); }
    catch (err) { toast(err.message, true); }
  };
  $("#logout").onclick = async () => { await api("POST", "/api/auth/logout").catch(() => {}); showAuth(); };

  const applyTheme = (t) => { if (t) document.documentElement.dataset.theme = t; else delete document.documentElement.dataset.theme; };
  try { applyTheme(localStorage.getItem("vpnmon-theme")); } catch {}
  $("#theme-toggle").onclick = () => {
    const dark = document.documentElement.dataset.theme
      ? document.documentElement.dataset.theme === "dark"
      : matchMedia("(prefers-color-scheme: dark)").matches;
    const t = dark ? "light" : "dark";
    applyTheme(t);
    try { localStorage.setItem("vpnmon-theme", t); } catch {}
    if (S.view === "overview") loadConcurrency();
  };

  // overview
  bindSeg("conc-range", () => { concDays = +segValue("conc-range", "days"); loadConcurrency(); });
  let resizeT;
  window.addEventListener("resize", () => {
    clearTimeout(resizeT);
    resizeT = setTimeout(() => S.state && S.view === "overview" && loadConcurrency(), 200);
  });

  // sessions
  $("#s-search").oninput = renderSessions;
  bindSeg("s-router", renderSessions);
  bindSort($("#s-table"), S.sessSort, renderSessions);
  $("#s-table tbody").onclick = (e) => {
    const tr = e.target.closest("tr");
    if (!tr) return;
    const s = S.state.sessions[+tr.dataset.i];
    const user = e.target.closest("[data-user]");
    if (user) { e.preventDefault(); openUser(user.dataset.user); return; }
    const act = e.target.closest("[data-act]");
    if (act && s) sessionAction(act.dataset.act, s);
  };

  // audit
  bindSeg("a-period", loadAudit);
  bindSeg("a-filter", renderAudit);
  $("#a-search").oninput = renderAudit;
  bindSort($("#a-table"), S.auditSort, renderAudit);
  $("#a-table tbody").onclick = (e) => {
    const cb = e.target.closest("[data-sel]");
    if (cb) {
      cb.checked ? S.auditSel.add(cb.dataset.sel) : S.auditSel.delete(cb.dataset.sel);
      cb.closest("tr").classList.toggle("selected", cb.checked);
      updateSelBar();
      return;
    }
    if (e.target.closest(".chk")) return;
    const tr = e.target.closest("tr[data-user]");
    if (tr) openUser(tr.dataset.user);
  };
  $("#a-all").onchange = (e) => {
    $$("#a-table tbody [data-sel]").forEach((cb) => { e.target.checked ? S.auditSel.add(cb.dataset.sel) : S.auditSel.delete(cb.dataset.sel); });
    renderAudit();
  };
  $("#a-copy").onclick = () => copyText([...S.auditSel].join("\n"), `Скопировано логинов: ${S.auditSel.size}`);
  $("#a-remove").onclick = async () => {
    const list = [...S.auditSel];
    const ok = await modal({
      title: `Убрать ${list.length} из списка?`,
      html: `<p>Логины пропадут из аудита (история сессий сохранится). На устройстве Cisco ничего не меняется.</p><pre>${esc(list.join(", "))}</pre>`,
      actions: [{ label: "Убрать", cls: "danger solid", value: true }],
    });
    if (!ok) return;
    try { const r = await api("POST", "/api/users/remove", { logins: list }); toast(`Убрано: ${r.removed}`); S.auditSel.clear(); loadAudit(); }
    catch (err) { toast(err.message, true); }
  };
  $("#a-import").onclick = async () => {
    const ok = await modal({
      title: "Импорт логинов",
      html: `<p class="muted small">Логины через запятую, пробел или с новой строки — например, выгрузка из AD. Они появятся в аудите, даже если ещё ни разу не подключались.</p><textarea id="imp-text" placeholder="ivanov&#10;petrov"></textarea>`,
      actions: [{ label: "Импортировать", cls: "primary", value: "go" }],
    });
    if (ok !== "go") return;
    const logins = ($("#imp-text")?.value || "").split(/[\s,;]+/).filter(Boolean);
    try { const r = await api("POST", "/api/users/import", { logins }); toast(`Добавлено: ${r.added}`); loadAudit(); }
    catch (err) { toast(err.message, true); }
  };

  // accounts cleanup
  $("#c-apply").onclick = () => loadCleanup($("#c-days").value);
  $("#c-days").addEventListener("keydown", (e) => { if (e.key === "Enter") loadCleanup($("#c-days").value); });
  $("#c-sync").onclick = async (e) => {
    const b = e.currentTarget;
    b.disabled = true;
    try {
      const r = await api("POST", "/api/users/sync");
      const errors = r.routers.filter((x) => x.error);
      toast(`Учёток в конфигах: ${r.found}, новых: ${r.added}${errors.length ? `. Ошибки: ${errors.map((x) => x.name).join(", ")}` : ""}`, errors.length > 0);
      loadCleanup($("#c-days").value);
    } catch (err) { toast(err.message, true); }
    finally { b.disabled = false; }
  };
  $("#c-exclude-save").onclick = async () => {
    try {
      await api("POST", "/api/settings", { cleanup_exclude: $("#c-exclude").value, cleanup_idle_days: Number($("#c-days").value) });
      toast("Исключения сохранены");
      loadCleanup($("#c-days").value);
    } catch (err) { toast(err.message, true); }
  };

  // drawer
  $$("#drawer [data-close]").forEach((el) => el.onclick = closeDrawer);

  // events
  bindSeg("e-type", loadEvents);
  $("#e-search").oninput = () => { clearTimeout(eventsTimer); eventsTimer = setTimeout(loadEvents, 250); };

  // router syslog
  bindSeg("sl-kind", loadSyslog);
  bindSeg("sl-sev", loadSyslog);
  $("#sl-noise").onchange = loadSyslog;
  $("#sl-search").oninput = () => { clearTimeout(syslogTimer); syslogTimer = setTimeout(loadSyslog, 250); };
  $("#sl-codes").onclick = (e) => {
    const b = e.target.closest("[data-code]");
    if (!b) return;
    S.syslogCode = b.dataset.code;
    loadSyslog();
  };

  // panel users
  $("#u-add").onclick = () => editWebUser({});
  $("#u-table tbody").onclick = async (e) => {
    const ed = e.target.closest("[data-uedit]");
    const del = e.target.closest("[data-udel]");
    if (ed) {
      const u = webUsersCache.find((x) => x.login === ed.dataset.uedit);
      await editWebUser(u);
    }
    if (del) {
      const ok = await modal({ title: `Удалить пользователя ${del.dataset.udel}?`, html: "<p>Он сразу потеряет доступ к панели.</p>",
        actions: [{ label: "Удалить", cls: "danger solid", value: true }] });
      if (!ok) return;
      try { await api("POST", "/api/web-users/delete", { login: del.dataset.udel }); toast("Пользователь удалён"); loadWebUsers(); }
      catch (err) { toast(err.message, true); }
    }
  };

  // settings
  $("#settings-form").onsubmit = saveSettings;
  $("#r-add").onclick = () => editRouter({});
  $("#r-table tbody").onclick = (e) => {
    const edit = e.target.closest("[data-edit]");
    const del = e.target.closest("[data-del]");
    const r = routersCache.find((x) => x.id === (edit || del)?.dataset[edit ? "edit" : "del"]);
    if (r && edit) editRouter(r);
    if (r && del) deleteRouter(r);
  };
  $("#tg-test").onclick = async () => {
    try { await api("POST", "/api/telegram/test"); toast("Тестовое сообщение отправлено"); }
    catch (err) { toast(err.message, true); }
  };
  $("#report-preview").onclick = async () => {
    try {
      const r = await api("GET", "/api/report/preview");
      modal({ title: "Еженедельный отчёт — предпросмотр", html: `<pre class="report">${esc(r.text)}</pre>${r.telegram_ready ? "" : `<p class="muted small">Чтобы отчёт отправлялся, укажите токен бота и chat_id и сохраните настройки.</p>`}`, wide: true });
    } catch (err) { toast(err.message, true); }
  };
  $("#report-send").onclick = async (e) => {
    const b = e.currentTarget;
    b.disabled = true;
    try { await api("POST", "/api/report/send"); toast("Отчёт отправлен в Telegram"); }
    catch (err) { toast(err.message, true); }
    finally { b.disabled = false; }
  };
  $("#restart").onclick = async () => {
    const ok = await modal({
      title: "Перезапустить сервер?",
      html: "<p>Сбор данных прервётся на несколько секунд. Если адрес панели меняется, откройте её по новому адресу.</p>",
      actions: [{ label: "Перезапустить", cls: "primary", value: true }],
    });
    if (!ok) return;
    const info = await api("GET", "/api/server/info").catch(() => null);
    await api("POST", "/api/server/restart").catch(() => {});
    clearInterval(S.pollTimer);
    setCollector("starting", "Перезапуск…");
    const target = info ? `${info.configured.web_https ? "https" : "http"}://${location.hostname}:${info.configured.web_port}/#/settings` : location.href;
    toast("Сервер перезапускается…");
    setTimeout(() => { location.href = target; }, 4000);
  };
  $("#backup-now").onclick = async (e) => {
    const b = e.currentTarget;
    b.disabled = true;
    try { const r = await api("POST", "/api/backup"); renderBackups(r.backups); toast(`Копия создана: ${r.name}`); }
    catch (err) { toast(err.message, true); }
    finally { b.disabled = false; }
  };
  $("#pw-form").onsubmit = async (e) => {
    e.preventDefault();
    const f = e.target;
    try { await api("POST", "/api/auth/password", { current: f.current.value, new: f.new.value }); f.reset(); toast("Пароль панели изменён"); }
    catch (err) { toast(err.message, true); }
  };
  $("#shutdown").onclick = async () => {
    const ok = await modal({
      title: "Остановить сервер?",
      html: "<p>Сбор статистики прекратится, пока сервер не будет запущен снова (Start-Server.bat или автозапуск).</p>",
      actions: [{ label: "Остановить", cls: "danger solid", value: true }],
    });
    if (!ok) return;
    await api("POST", "/api/server/shutdown").catch(() => {});
    clearInterval(S.pollTimer);
    setCollector("error", "Сервер остановлен");
    toast("Сервер остановлен");
  };

  // keyboard
  document.addEventListener("keydown", (e) => {
    if (e.key === "Escape") { closeDrawer(); $("#modal").classList.add("hidden"); }
    if (e.key === "/" && !/INPUT|TEXTAREA|SELECT/.test(document.activeElement.tagName)) {
      e.preventDefault();
      if (S.view !== "sessions") location.hash = "#/sessions";
      setTimeout(() => $("#s-search").focus(), 0);
    }
  });
}

wire();
api("GET", "/api/auth/status")
  .then((st) => (st.authenticated ? start() : showAuth()))
  .catch(() => { document.body.textContent = "Сервер недоступен."; });
