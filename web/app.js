/* HunterStick console — vanilla SPA over the read-only JSON API.
 * No dependencies, no build step. Every untrusted string is placed with
 * textContent/setAttribute (never string-into-innerHTML); the only innerHTML
 * uses are (a) generated SVG built from numbers and escaped labels and
 * (b) progress_html, which the backend renders escaped-first.
 */
"use strict";

/* ---------------------------------------------------------------- helpers */
const $ = s => document.querySelector(s);

function el(tag, attrs = {}, ...kids) {
  const n = document.createElement(tag);
  for (const [k, v] of Object.entries(attrs || {})) {
    if (v == null) continue;
    if (k === "cls") n.className = v;
    else if (k === "text") n.textContent = v;
    else if (k.startsWith("on") && typeof v === "function") n.addEventListener(k.slice(2), v);
    else n.setAttribute(k, v);
  }
  for (const kid of kids.flat(9)) {
    if (kid == null || kid === false) continue;
    n.append(kid.nodeType ? kid : document.createTextNode(kid));
  }
  return n;
}

const esc = s => String(s).replace(/[&<>"']/g, c => (
  { "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));
const fmt = n => (n == null ? "—" : Number(n).toLocaleString("en-US"));
const nfmt = n => (n == null ? "—" : n >= 100000 ? (n / 1000).toFixed(0) + "k"
  : n >= 10000 ? (n / 1000).toFixed(1) + "k" : Number(n).toLocaleString("en-US"));
const num = v => parseFloat(String(v == null ? "" : v).replace(/[^\d.-]/g, "")) || 0;
const clampBar = (v, max) => Math.max(2, Math.round((v / (max || 1)) * 100));

function ago(iso) {
  if (!iso) return "—";
  const t = Date.parse(iso.includes("T") ? iso : iso + "T00:00:00");
  if (isNaN(t)) return iso;
  const s = Math.max(0, (Date.now() - t) / 1000);
  if (s < 60) return Math.round(s) + "s ago";
  if (s < 3600) return Math.round(s / 60) + "m ago";
  if (s < 86400) return Math.round(s / 3600) + "h ago";
  return Math.round(s / 86400) + "d ago";
}

/* ---------------------------------------------------------------- icons */
const IC = {
  globe: '<circle cx="12" cy="12" r="9"/><path d="M3 12h18M12 3a15 15 0 0 1 0 18M12 3a15 15 0 0 0 0 18"/>',
  radio: '<circle cx="12" cy="12" r="2"/><path d="M7.8 16.2a6 6 0 0 1 0-8.4M16.2 7.8a6 6 0 0 1 0 8.4M4.9 19.1a10 10 0 0 1 0-14.2M19.1 4.9a10 10 0 0 1 0 14.2"/>',
  layers: '<path d="M12 3 3 8l9 5 9-5-9-5Z"/><path d="m3 13 9 5 9-5"/>',
  target: '<circle cx="12" cy="12" r="9"/><circle cx="12" cy="12" r="5"/><circle cx="12" cy="12" r="1"/>',
  bug: '<path d="M8 6l-2-2M16 6l2-2M8 16l-3 3M16 16l3 3"/><rect x="8" y="6" width="8" height="12" rx="4"/><path d="M8 11H3M21 11h-5M8 15H4M20 15h-4"/>',
  flask: '<path d="M9 3h6M10 3v5L5 19a2 2 0 0 0 2 3h10a2 2 0 0 0 2-3L14 8V3"/><path d="M7.5 15h9"/>',
  user: '<circle cx="12" cy="8" r="4"/><path d="M4 21c1.5-3.5 4.5-5 8-5s6.5 1.5 8 5"/>',
  radar: '<circle cx="12" cy="12" r="9"/><circle cx="12" cy="12" r="5"/><path d="M12 12 18 6"/><circle cx="12" cy="12" r="1"/>',
  clock: '<circle cx="12" cy="12" r="9"/><path d="M12 7v5l3 3"/>',
  shield: '<path d="M12 3 4 6v6c0 5 3.5 8 8 9 4.5-1 8-4 8-9V6l-8-3Z"/>',
};
function icon(name, size = 16) {
  const d = IC[name] || IC.target;
  return `<svg width="${size}" height="${size}" viewBox="0 0 24 24" fill="none" \
stroke="currentColor" stroke-width="1.7" stroke-linecap="round" stroke-linejoin="round">${d}</svg>`;
}
function iconEl(name, size = 16) {
  const w = document.createElement("div");
  w.innerHTML = icon(name, size);
  return w.firstChild;
}

/* ---------------------------------------------------------------- chips */
function chip(txt, cls = "", title = null) {
  return el("span", { cls: "chip " + cls, title }, txt);
}
const RUN_STATUS = {
  "running": ["bad", "RUNNING"],
  "done": ["ok", "done"],
  "complete-for-this-run": ["ok", "complete"],
  "partial": ["warn", "partial"],
  "failed": ["bad", "failed"],
};
function runStatusChip(st) {
  const m = RUN_STATUS[st] || [null, st || "—"];
  const live = st === "running";
  return el("span", { cls: "chip " + (m[0] || ""), title: st },
    live ? el("i", { cls: "dotp live" }) : null, m[1]);
}
function hypChip(st) {
  const cls = { open: "info", testing: "warn", confirmed: "ok", rejected: "mut" }[st] || "";
  return chip(st || "unstated", cls);
}

/* ---------------------------------------------------------------- charts */
function fillDays(activity, days) {
  const map = new Map(activity.map(a => [a.date, a.n]));
  const out = [];
  const d = new Date();
  d.setHours(12, 0, 0, 0);
  for (let i = days - 1; i >= 0; i--) {
    const dt = new Date(d - i * 864e5);
    const k = dt.toISOString().slice(0, 10);
    out.push({ date: k, n: map.get(k) || 0 });
  }
  return out;
}

function sparkSVG(activity, w = 150, h = 34, days = 21) {
  const data = fillDays(activity || [], days);
  const max = Math.max(1, ...data.map(x => x.n));
  const step = w / (data.length - 1 || 1);
  const pts = data.map((x, i) => `${(i * step).toFixed(1)},${(h - 3 - (x.n / max) * (h - 7)).toFixed(1)}`);
  const last = data.filter(x => x.n).slice(-1)[0];
  return `<svg class="chart" width="${w}" height="${h}" viewBox="0 0 ${w} ${h}">
    <polyline points="${pts.join(" ")}" fill="none" stroke="var(--acc)" stroke-width="1.6"
      stroke-linejoin="round" stroke-linecap="round" opacity=".9"/>
    <polyline points="0,${h} ${pts.join(" ")} ${w},${h}" fill="color-mix(in srgb,var(--acc) 12%,transparent)" stroke="none"/>
  </svg>`;
}

function barsSVG(activity, w = 640, h = 130, days = 30) {
  const data = fillDays(activity || [], days);
  const max = Math.max(1, ...data.map(x => x.n));
  const bw = w / days, ch = h - 22;
  const bars = data.map((x, i) => {
    const bh = Math.round((x.n / max) * (ch - 8)) + (x.n ? 0 : 0);
    const y = ch - Math.max(bh, x.n ? 3 : 1);
    return `<rect class="bar" x="${(i * bw + bw * 0.18).toFixed(1)}" y="${y.toFixed(1)}"
      width="${(bw * 0.64).toFixed(1)}" height="${Math.max((ch - y), 1).toFixed(1)}" rx="2">
      <title>${esc(x.date)} — ${x.n} run${x.n === 1 ? "" : "s"}</title></rect>`;
  }).join("");
  const lbl = [0, Math.floor(days / 2), days - 1].map(i => {
    const x = i * bw + bw / 2;
    return `<text class="axis" x="${x.toFixed(0)}" y="${h - 6}" text-anchor="middle">${esc(data[i].date.slice(5))}</text>`;
  }).join("");
  const total = data.reduce((a, b) => a + b.n, 0);
  return `<svg class="chart" width="100%" viewBox="0 0 ${w} ${h}" preserveAspectRatio="none">
    <defs><linearGradient id="gradBar" x1="0" y1="1" x2="0" y2="0">
      <stop offset="0" stop-color="color-mix(in srgb,var(--acc) 45%,transparent)"/>
      <stop offset="1" stop-color="var(--acc)"/></linearGradient></defs>
    ${bars}${lbl}
    <text class="axis" x="${w}" y="${h - 6}" text-anchor="end">${total} runs / ${days}d</text>
  </svg>`;
}

function donutSVG(parts, size = 132) {
  const tot = parts.reduce((a, p) => a + p.n, 0);
  const r = size / 2 - 12, c = 2 * Math.PI * r;
  let off = 0;
  const segs = tot ? parts.filter(p => p.n).map(p => {
    const len = (p.n / tot) * c;
    const s = `<circle cx="${size / 2}" cy="${size / 2}" r="${r}" fill="none"
      stroke="${p.color}" stroke-width="13" stroke-dasharray="${len.toFixed(2)} ${(c - len).toFixed(2)}"
      stroke-dashoffset="${(-off).toFixed(2)}" transform="rotate(-90 ${size / 2} ${size / 2})">
      <title>${esc(p.label)} — ${p.n}</title></circle>`;
    off += len;
    return s;
  }).join("") : `<circle cx="${size/2}" cy="${size/2}" r="${r}" fill="none" stroke="var(--panel-3)" stroke-width="13"/>`;
  return `<svg width="${size}" height="${size}" viewBox="0 0 ${size} ${size}">
    ${segs}
    <text x="${size / 2}" y="${size / 2 - 3}" text-anchor="middle" font-size="21" font-weight="650"
      fill="var(--text)">${tot}</text>
    <text x="${size / 2}" y="${size / 2 + 15}" text-anchor="middle" font-size="9.5"
      fill="var(--mut)" letter-spacing="1">TOTAL</text>
  </svg>`;
}

/* ---------------------------------------------------------------- tables */
const TABLES = [];   // live registries for the global filter
const BIGS = [];     // chunked tables (hosts/urls) — apply(term) re-renders matches

function mkTable({ id, cols, rows, defaultSort = null, empty = null }) {
  const state = { key: defaultSort ? defaultSort.key : null, dir: defaultSort ? defaultSort.dir : 1 };
  const tbody = el("tbody");
  const thead = el("thead");

  function value(row, col) {
    return col.value ? col.value(row) : row[col.key];
  }
  function renderRows() {
    const data = [...rows];
    if (state.key) {
      const col = cols.find(c => c.key === state.key);
      data.sort((a, b) => {
        const va = value(a, col), vb = value(b, col);
        if (col.sort === "num") return (num(va) - num(vb)) * state.dir;
        return String(va == null ? "" : va).localeCompare(String(vb == null ? "" : vb)) * state.dir;
      });
    }
    tbody.textContent = "";
    if (!data.length) {
      tbody.append(el("tr", null, el("td", { colspan: cols.length },
        el("div", { cls: "empty", text: empty || "No rows." }))));
      return;
    }
    for (const row of data) {
      const tr = el("tr");
      const hay = [];
      for (const col of cols) {
        const td = el("td", { cls: col.cls || "" });
        const v = value(row, col);
        if (col.render) td.append(col.render(row, v));
        else td.textContent = v == null || v === "" ? "—" : v;
        hay.push(td.textContent);
        tr.append(td);
      }
      tr.dataset.hay = hay.join(" ").toLowerCase();
      tr.dataset.sort = cols.map(c => String(value(row, c))).join(" ");
      tbody.append(tr);
    }
  }
  const trh = el("tr");
  for (const col of cols) {
    const arr = el("span", { cls: "arr" });
    const th = el("th", {
      cls: (col.sort === false ? "" : "sortable ") + (col.cls || ""),
      onclick: col.sort === false ? null : () => {
        if (state.key === col.key) state.dir *= -1;
        else { state.key = col.key; state.dir = col.num ? 1 : 1; }
        TABLES_HEADS();
        renderRows();
      },
    }, col.label, arr);
    th._arr = arr; th._key = col.key;
    trh.append(th);
  }
  thead.append(trh);
  renderRows();
  function TABLES_HEADS() {
    [...trh.children].forEach(th => { th._arr.textContent = th._key === state.key ? (state.dir > 0 ? "▲" : "▼") : ""; });
  }
  TABLES_HEADS();
  const wrap = el("div", { cls: "tblwrap" }, el("table", { cls: "tbl" }, thead, tbody));
  const reg = { wrap, tbody, id };
  TABLES.push(reg);
  return { wrap, registry: reg, resort: renderRows };
}

function resetTables() { TABLES.length = 0; BIGS.length = 0; }

function applyFilter(term) {
  const t = (term || "").trim().toLowerCase();
  let shown = 0, total = 0;
  for (const { tbody } of TABLES) {
    for (const tr of tbody.children) {
      const hit = !t || (tr.dataset.hay || "").includes(t);
      tr.style.display = hit ? "" : "none";
      total++; if (hit) shown++;
    }
  }
  for (const big of BIGS) {
    const r = big.apply(t);
    shown += r.shown; total += r.total;
  }
  return { shown, total, term: t };
}

/* A table over thousands of rows: render in chunks, re-render on filter.
 * Same honesty as everywhere — the note always says how many of how many are shown. */
function mkBigTable({ id, cols, rows, chunk = 400 }) {
  let term = "", shown = 0;
  const tbody = el("tbody");
  const note = el("div", { cls: "small mut2", style: "margin-top:8px" });
  const more = el("button", {
    cls: "chip", style: "cursor:pointer;margin-top:8px",
    onclick: () => render(false),
  }, "show more ▾");
  const matches = (row) => !term || row._hay.includes(term);
  const prepared = rows.map(row => {
    row._hay = cols.map(c => (c.value ? c.value(row) : row[c.key]) ?? "").join(" ").toLowerCase();
    return row;
  });

  function buildRow(row) {
    const tr = el("tr");
    for (const col of cols) {
      const td = el("td", { cls: col.cls || "" });
      const v = col.value ? col.value(row) : row[col.key];
      if (col.render) td.append(col.render(row, v));
      else td.textContent = v == null || v === "" ? "—" : v;
      tr.append(td);
    }
    return tr;
  }
  function render(reset) {
    if (reset) { shown = 0; tbody.textContent = ""; }
    const list = prepared.filter(matches);
    let n = 0;
    for (let i = shown; i < list.length && n < chunk; i++, n++) tbody.append(buildRow(list[i]));
    shown += n;
    more.style.display = shown < list.length ? "" : "none";
    note.textContent = `${fmt(shown)} of ${fmt(list.length)} row(s) shown`
      + (term ? ` matching "${term}"` : "")
      + (term && !list.length ? " — nothing here, which is not the same as nothing in the brain" : "");
  }
  render(true);
  const thead = el("thead", null, el("tr", null,
    ...cols.map(c => el("th", { cls: c.cls || "" }, c.label))));
  const wrap = el("div", null,
    el("div", { cls: "tblwrap" }, el("table", { cls: "tbl" }, thead, tbody)),
    note, more);
  BIGS.push({ id, apply(t) { term = t; render(true); return { shown, total: prepared.filter(matches).length }; } });
  return wrap;
}

/* raw markdown-table rows rendered by column index */
function rawTable({ id, header, rows, picks, empty = null, defaultSort = null }) {
  const cols = picks.map(p => ({
    key: "c" + p.i, label: p.label, cls: p.cls, sort: p.sort || "str",
    value: r => (p.i < r.length ? r[p.i] : ""),
    render: p.render,
  }));
  return mkTable({ id, cols, rows: rows.map(r => Object.fromEntries(cols.map(c => [c.key, c.value(r)]))), defaultSort, empty }).wrap;
}

function httpChip(status) {
  if (!status) return el("span", { cls: "mut2", text: "—" });
  const code = parseInt(status, 10);
  const cls = isNaN(code) ? "info" : code >= 500 ? "bad" : code >= 400 ? "warn"
    : code >= 300 ? "info" : "ok";
  return chip(String(status).slice(0, 40), cls, status);
}

function hostLink(targetName, host) {
  return el("a", { href: "#/t/" + encodeURIComponent(targetName) + "/app/" + encodeURIComponent(host), cls: "mono", text: host });
}

/* ---------------------------------------------------------------- banners & kpis */
function banner(kind, ...kids) {
  return el("div", { cls: "banner " + kind }, ...kids);
}
function kpi({ v, l, ic, cls = "", sub = null, title = null }) {
  return el("div", { cls: "card kpi " + cls, title },
    el("div", { cls: "v", text: v }),
    el("div", { cls: "l", text: l }),
    sub ? el("div", { cls: "sub", text: sub }) : null,
    el("span", { cls: "ic" }, iconEl(ic)));
}

function funnelCard(funnel, stages) {
  const rows = stages.map(([key, label]) => {
    const st = funnel[key] || { state: "missing", count: null };
    return { key, label, ...st };
  });
  const base = rows.find(r => r.count != null && r.count > 0);
  const wrap = el("div", { cls: "card" }, el("h3", null, "Recon funnel",
    el("span", { cls: "right", text: "computed from the files, not index.md" })));
  const box = el("div", { cls: "funnel" });
  for (const r of rows) {
    const missing = r.state === "missing";
    const empty = r.state === "empty";
    const demoted = r.state === "demoted";
    const pct = base && base.count ? (r.count ? ((r.count / base.count) * 100).toFixed(1) + "%" : "—") : "—";
    const bar = el("div", {
      cls: "fbar " + (missing ? "missing" : empty ? "empty" : ""),
      title: r.state === "prose" ? "reasoning file — no countable rows" : r.state,
      text: missing ? "missing" : empty ? "0" : (fmt(r.count) + (demoted ? " ⇡" : "")),
    });
    if (!missing && !empty) bar.style.width = "calc(" + Math.max(1.5, (r.count / (base ? base.count : 1)) * 100).toFixed(1) + "% - 0px)";
    else bar.style.width = "90px";
    box.append(el("div", { cls: "frow" },
      el("span", { cls: "fl", text: r.label }),
      bar,
      el("span", { cls: "fpct", text: demoted ? "on VPS" : pct })));
  }
  wrap.append(box);
  return wrap;
}

/* ---------------------------------------------------------------- state & api */
const S = { view: "fleet", target: null, tab: "overview", appHost: null, ov: null, tg: null, ap: null, vps: null, loadedAt: 0 };

async function api(path) {
  const r = await fetch(path, { headers: { Accept: "application/json" } });
  if (!r.ok) throw new Error((await r.json().catch(() => ({}))).error || r.status);
  return r.json();
}

/* ---------------------------------------------------------------- shell */
function renderShell() {
  document.body.textContent = "";
  document.body.append(el("div", { id: "app" },
    el("aside", { id: "side" }),
    el("div", { id: "mainwrap" }, el("main", { id: "main" }))));
}

function renderSide(ov) {
  const side = $("#side");
  side.textContent = "";
  const t = ov ? ov.totals : {};
  side.append(el("div", { cls: "brand" },
    el("span", { cls: "logo" }, iconEl("radar", 16)),
    el("div", null, el("b", { text: "HunterStick" }), el("span", { cls: "tag", text: "ASM console" }))));
  side.append(el("div", { cls: "side-kpis" },
    el("div", { cls: "side-kpi" }, el("b", { text: fmt(t.targets) }), el("span", { text: "targets" })),
    el("div", { cls: "side-kpi" }, el("b", { text: fmt(t.open_runs) }), el("span", { text: "open runs" })),
    el("div", { cls: "side-kpi" }, el("b", { text: fmt(t.findings_confirmed) }), el("span", { text: "confirmed" })),
    el("div", { cls: "side-kpi" }, el("b", { text: fmt(t.probes) }), el("span", { text: "probes" }))));
  const nav = el("div", { cls: "nav" });
  nav.append(el("span", { cls: "navlbl", text: "workspace" }));
  nav.append(el("a", { href: "#/", cls: S.view === "fleet" ? "on" : "" },
    el("i", { cls: "dot", style: "background:var(--acc)" }), el("span", { cls: "nm", text: "Fleet overview" })));
  nav.append(el("span", { cls: "navlbl", text: "targets" }));
  for (const c of (ov ? ov.targets : [])) {
    const dot = c.open_runs ? "run" : c.stale ? "stale" : "";
    nav.append(el("a", {
      href: "#/t/" + encodeURIComponent(c.name),
      cls: S.view !== "fleet" && S.target === c.name ? "on" : "",
      title: c.program || c.scope || c.name,
    },
      el("i", { cls: "dot " + dot }),
      el("span", { cls: "nm", text: c.name }),
      c.open_runs ? el("span", { cls: "bd", text: String(c.open_runs) }) : null));
    for (const a of (c.apps || [])) {
      nav.append(el("a", {
        href: "#/t/" + encodeURIComponent(c.name) + "/app/" + encodeURIComponent(a.host),
        cls: S.view === "app" && S.target === c.name && S.appHost === a.host ? "on" : "",
        style: "padding-left:26px;font-size:12.5px;color:var(--mut)",
        title: "application brain — " + a.host,
      },
        el("i", { cls: "dot", style: "background:var(--acc)" }),
        el("span", { cls: "nm", text: a.host })));
    }
  }
  side.append(nav);
  side.append(el("div", { cls: "side-foot" },
    el("span", null, el("i", { cls: "dotp", style: `background:${S.vps === "ok" ? "var(--ok)" : "var(--warn)"}` }),
      " VPS bridge: " + (S.vps === "ok" ? "live (read-only)" : "not configured")),
    el("br"), "local · read-only · recomputed per request",
    el("br"), "accounts summarized — never rendered"));
}

function topbar(crumbs, placeholder) {
  const bar = el("div", { cls: "topbar" },
    el("div", { cls: "crumb" }, ...crumbs),
    el("div", { cls: "search" },
      el("input", { id: "q", type: "search", autocomplete: "off", spellcheck: "false",
        placeholder, oninput: onSearch, onkeydown: e => { if (e.key === "Escape") { e.target.value = ""; onSearch(e); } } }),
      el("span", { cls: "hint", text: "/" })),
    el("div", { cls: "live" },
      el("i", { cls: "pip" }),
      el("span", { id: "updated", text: "loading…" })));
  return bar;
}

function onSearch(e) {
  const { shown, total } = applyFilter(e.target.value);
  const hint = $("#qhint");
  if (hint) {
    hint.textContent = e.target.value.trim()
      ? `${shown} of ${total} rows match — nothing here is not nothing in the brain` : "";
  }
}

/* ---------------------------------------------------------------- fleet view */
function renderFleet(ov) {
  resetTables();
  const t = ov.totals;
  const main = $("#main");
  main.textContent = "";
  main.append(topbar([el("b", { text: "Fleet overview" }),
    el("span", { text: `${t.targets} target${t.targets === 1 ? "" : "s"}` })],
    "filter targets by name, scope, program…"));

  const cards = el("div", { cls: "grid kpis" });
  cards.append(
    kpi({ v: fmt(t.subdomains), l: "subdomains", ic: "globe", sub: t.endpoints ? null : "run subdomain-enumeration" }),
    kpi({ v: fmt(t.live_hosts), l: "live hosts", ic: "radio" }),
    kpi({ v: fmt(t.endpoints), l: "endpoints", ic: "layers" }),
    kpi({ v: fmt(t.surface), l: "surface entries", ic: "target" }),
    kpi({ v: fmt(t.findings_confirmed), l: "findings", ic: "bug",
      sub: `+${fmt(t.findings_draft)} draft · ${fmt(t.findings_rejected)} rejected`, cls: t.findings_confirmed ? "" : "dim" }),
    kpi({ v: fmt(t.open_runs), l: "open runs", ic: "radar",
      cls: t.open_runs ? "bad" : t.resume_points ? "warn" : "", sub: t.resume_points ? `+${t.resume_points} resume point${t.resume_points === 1 ? "" : "s"}` : "all runs closed" }));
  main.append(cards);

  if (t.blockers) main.append(banner("warn",
    el("b", { text: `${t.blockers} blocker${t.blockers === 1 ? "" : "s"} across the fleet. ` }),
    "Blockers are named per target below — an unblocked preflight beats a fast one."));

  // charts row
  const chard = el("div", { cls: "card" }, el("h3", null, "Run activity",
    el("span", { cls: "right", text: "runs closed per day, last 30d" })));
  const holder = document.createElement("div");
  holder.innerHTML = barsSVG(ov.activity);
  chard.append(holder);
  const donutParts = [
    { n: t.hyp_open, label: "open", color: "var(--info)" },
    { n: t.hyp_testing, label: "testing", color: "var(--warn)" },
    { n: t.hyp_confirmed, label: "confirmed", color: "var(--ok)" },
    { n: t.hyp_rejected, label: "rejected", color: "var(--mut-2)" },
  ];
  const dwrap = el("div", { cls: "donut-wrap" });
  const dh = document.createElement("div");
  dh.innerHTML = donutSVG(donutParts);
  dwrap.append(dh, el("div", { cls: "donut-nums" },
    ...donutParts.map(p => el("div", null,
      el("span", { cls: "legend-i", style: `display:inline-block;width:9px;height:9px;border-radius:3px;background:${p.color};margin-right:7px` }),
      el("b", { text: fmt(p.n) }), p.label))));
  const dcard = el("div", { cls: "card" }, el("h3", null, "Hypotheses"), dwrap);
  main.append(el("div", { cls: "grid row2" }, chard, dcard));

  const sum = { subdomains: 0, live_hosts: 0, urls: 0, endpoints: 0 };
  main.append(funnelCard({ subdomains: { state: t.subdomains ? "lines" : "missing", count: t.subdomains || null },
    live_hosts: { state: t.live_hosts ? "lines" : "missing", count: t.live_hosts || null },
    urls: { state: t.urls ? "lines" : "missing", count: t.urls || null },
    endpoints: { state: t.endpoints ? "rows" : "missing", count: t.endpoints || null } },
    [["subdomains", "subdomains"], ["live_hosts", "live hosts"], ["urls", "urls"], ["endpoints", "endpoints"]]));

  // target cards
  main.append(el("div", { cls: "section", text: "Targets" }));
  const grid = el("div", { cls: "grid tgrid", id: "tgrid" });
  for (const c of ov.targets) grid.append(targetCard(c));
  if (!ov.targets.length) grid.append(el("div", { cls: "card empty" }, "No target brains under targets/ — initialize one first."));
  main.append(grid);
  main.append(el("div", { cls: "foot" },
    `Generated live from targets/ by tools/dashboard-server.py · missing ≠ 0 — a dashed or hatched number means the producing phase never ran, not that it found nothing.`));
  updateStamp();
}

function targetCard(c) {
  const f = c.funnel;
  const stat = (key) => {
    const st = f[key];
    if (!st || st.state === "missing") return { v: "—", dim: true };
    return { v: nfmt(st.count), dim: st.state === "empty" };
  };
  const s1 = stat("subdomains"), s2 = stat("live_hosts");
  const chips = el("div", { cls: "chips" });
  if (c.open_runs) chips.append(chip(`${c.open_runs} running`, "bad"));
  if (c.resume_points) chips.append(chip(`${c.resume_points} resume`, "warn"));
  if (c.stale) chips.append(chip(`${c.age_days}d stale`, "warn"));
  if (c.blockers.length) chips.append(chip(`${c.blockers.length} blocker${c.blockers.length === 1 ? "" : "s"}`, "bad"));
  if (!c.stale && !c.open_runs) chips.append(chip("healthy", "ok"));

  const spark = document.createElement("div");
  spark.className = "spark";
  spark.innerHTML = sparkSVG(c.activity);

  return el("div", { cls: "card tcard", "data-hay": (c.name + " " + (c.program || "") + " " + (c.scope || "")).toLowerCase() },
    el("div", { cls: "head" },
      el("a", { href: "#/t/" + encodeURIComponent(c.name), text: c.name }),
      c.scope ? el("span", { cls: "scope", title: c.scope, text: c.scope }) : null),
    chips,
    el("div", { cls: "tstats" },
      el("div", null, el("b", { cls: s1.dim ? "dim" : "", text: s1.v }), el("span", { text: "subdomains" })),
      el("div", null, el("b", { cls: s2.dim ? "dim" : "", text: s2.v }), el("span", { text: "live" })),
      el("div", null, el("b", { text: fmt(c.surface) }), el("span", { text: "surface" })),
      el("div", null, el("b", { text: fmt(c.findings.confirmed) }), el("span", { text: "findings" }))),
    el("div", { cls: "tfoot" },
      el("span", { text: `updated ${c.updated || "—"}${c.age_days != null ? ` (${c.age_days}d)` : ""}` }),
      c.last_run ? el("span", { cls: "mut2", text: `last: ${c.last_run.id} ${c.last_run.phase}` }) : null,
      spark));
}

/* ---------------------------------------------------------------- target view */
const TABS = ["overview", "hosts", "endpoints", "runs", "surface", "backlog", "logs", "vps", "progress", "files"];
const TAB_LABELS = { vps: "VPS raw" };

function renderTarget(tg) {
  resetTables();
  const m = tg.meta;
  const main = $("#main");
  main.textContent = "";
  main.append(topbar([
    el("a", { href: "#/", text: "Fleet" }),
    el("span", { text: "/" }),
    el("b", { text: m.name }),
    el("span", { cls: "mut", text: m.scope_type || "" }),
  ], "filter this tab's tables — host, path, class, tool…"));

  main.append(el("h1", { style: "margin:0 0 4px;font-size:24px;letter-spacing:-.01em" }, m.name,
    m.scope ? el("span", { cls: "scope", title: m.scope, text: m.scope, style: "margin-left:10px;font-size:12px" }) : null));
  if (m.last_activity) main.append(el("p", { cls: "mut small", style: "margin:0 0 8px;max-width:90ch", text: m.last_activity }));

  if (m.stale) main.append(banner("warn",
    el("b", { text: `Brain last updated ${m.updated} — ${m.age_days} days ago. ` }),
    "State the age of the recon before testing anything off this page."));
  if (m.blockers.length) main.append(banner("bad", el("b", { text: "Blocking" }),
    el("ul", null, ...m.blockers.map(b => el("li", { text: b })))));
  if (m.principals < 2) main.append(banner("warn",
    el("b", { text: `${m.principals} usable principal(s). ` }),
    "Authz / IDOR / multi-tenant / privesc are blocked, not untested — a one-account \u201cnot vulnerable\u201d is not a result."));
  if (m.suggested_next) main.append(banner("acc", el("b", { text: "Suggested next — a suggestion, not a queue: " }), m.suggested_next));

  // KPIs
  const f = m.funnel;
  const fk = (key, l, ic) => {
    const st = f[key] || { state: "missing" };
    const missing = st.state === "missing", empty = st.state === "empty";
    return kpi({
      v: missing ? "—" : empty ? "0" : fmt(st.count) + (st.state === "demoted" ? " ⇡" : ""),
      l, ic, cls: missing ? "dim" : "", sub: missing ? "phase never ran" : null,
    });
  };
  const cards = el("div", { cls: "grid kpis" });
  cards.append(
    fk("subdomains", "subdomains", "globe"),
    fk("live_hosts", "live hosts", "radio"),
    fk("endpoints", "endpoints", "layers"),
    kpi({ v: fmt(m.surface), l: "surface entries", ic: "target" }),
    kpi({ v: fmt(m.probes), l: "probes logged", ic: "flask" }),
    kpi({ v: fmt(m.hypotheses.open), l: "hypotheses open", ic: "clock", sub: `of ${Object.values(m.hypotheses).reduce((a, b) => a + b, 0)} total` }),
    kpi({ v: fmt(m.findings.confirmed), l: "findings", ic: "bug", sub: `+${m.findings.draft} draft · ${m.findings.rejected} rejected` }),
    kpi({ v: fmt(m.principals), l: "usable principals", ic: "user", cls: m.principals < 2 ? "warn" : "" }));
  main.append(cards);

  // tabs
  const tabs = el("div", { cls: "tabs" });
  const counts = { runs: tg.runs_total, surface: tg.surface.total, backlog: tg.hypotheses.rows.length, logs: tg.logs.length,
    hosts: m.funnel.live_hosts && m.funnel.live_hosts.count != null ? m.funnel.live_hosts.count : null,
    endpoints: m.funnel.endpoints && m.funnel.endpoints.count != null ? m.funnel.endpoints.count : null };
  for (const tb of TABS) {
    const n = counts[tb];
    tabs.append(el("a", {
      href: "#/t/" + encodeURIComponent(m.name) + "/" + tb,
      cls: S.tab === tb ? "on" : "",
    }, TAB_LABELS[tb] || (tb[0].toUpperCase() + tb.slice(1)), n != null ? el("span", { cls: "n", text: nfmt(n) }) : null));
  }
  main.append(tabs);
  const panel = el("div", { id: "panel" });
  main.append(panel, el("p", { cls: "sub small mut2", id: "qhint", style: "min-height:1.2em;margin:6px 0 0" }));
  const R = { overview: tabOverview, hosts: tabHosts, endpoints: tabEndpoints, runs: tabRuns, surface: tabSurface, backlog: tabBacklog, logs: tabLogs, vps: tabVps, progress: tabProgress, files: tabFiles };
  (R[S.tab] || tabOverview)(panel, tg);
  updateStamp();
}

/* ------- tabs ------- */
function tabOverview(p, tg) {
  const m = tg.meta;
  const chard = el("div", { cls: "card" }, el("h3", null, "Run activity"));
  const h = document.createElement("div");
  h.innerHTML = barsSVG(m.activity);
  chard.append(h);
  const parts = [
    { n: m.hypotheses.open, label: "open", color: "var(--info)" },
    { n: m.hypotheses.testing, label: "testing", color: "var(--warn)" },
    { n: m.hypotheses.confirmed, label: "confirmed", color: "var(--ok)" },
    { n: m.hypotheses.rejected, label: "rejected", color: "var(--mut-2)" },
  ];
  const dh = document.createElement("div");
  dh.innerHTML = donutSVG(parts);
  const dcard = el("div", { cls: "card" }, el("h3", null, "Hypotheses"),
    el("div", { cls: "donut-wrap" }, dh,
      el("div", { cls: "donut-nums" }, ...parts.map(x => el("div", null,
        el("span", { style: `display:inline-block;width:9px;height:9px;border-radius:3px;background:${x.color};margin-right:7px` }),
        el("b", { text: fmt(x.n) }), x.label)))));
  p.append(el("div", { cls: "grid row2" }, chard, dcard));
  p.append(funnelCard(m.funnel, [["subdomains", "subdomains"], ["live_hosts", "live hosts"],
    ["urls", "urls"], ["endpoints", "endpoints"]]));

  // coverage
  const by = tg.tested.by_result || {};
  const chips = el("div", { cls: "chips" });
  for (const [k, v] of Object.entries(by)) {
    chips.append(chip(`${k}: ${v}`,
      k === "vuln" ? "bad" : k === "not-vuln" ? "ok" : "mut"));
  }
  p.append(el("div", { cls: "card" }, el("h3", null, "Probes by result",
    el("span", { cls: "right", text: `${tg.tested.total} row(s) in tested.md` })),
    tg.tested.total ? chips : el("div", { cls: "empty" }, "No probes logged yet — coverage is 0%, not unknown.")));

  // recent runs
  const recent = tg.runs.slice(0, 8);
  p.append(el("div", { cls: "card" }, el("h3", null, "Recent runs",
    el("span", { cls: "right" }, el("a", { href: "#/t/" + encodeURIComponent(m.name) + "/runs", text: "all runs →" }))),
    runsTable(recent, "ov-runs")));

  // scope card
  const sc = tg.scope || {};
  const scopeCard = el("div", { cls: "card" }, el("h3", null, "Scope & rules of engagement"));
  if (sc.statement) scopeCard.append(el("p", { cls: "mono", style: "margin:4px 0", text: sc.statement }));
  if (sc.exclusions && !/none stated/.test(sc.exclusions)) scopeCard.append(el("p", { cls: "small mut" }, "Exclusions: ", el("code", { text: sc.exclusions })));
  if (sc.decisions && sc.decisions.length) {
    const t2 = mkTable({
      id: "decisions", cols: [
        { key: 0, label: "date", cls: "num" },
        { key: 1, label: "decision", cls: "wrap cellmain" },
        { key: 2, label: "why", cls: "wrap dim" },
      ], rows: sc.decisions.map(r => ({ 0: r[0], 1: r[1], 2: r[2] })),
    });
    scopeCard.append(el("p", { cls: "small mut", style: "margin:10px 0 4px", text: "Standing decisions (the hunter's own instructions — they bind):" }), t2.wrap);
  }
  const chips2 = el("div", { cls: "chips", style: "margin-top:10px" });
  if (sc.attribution) chips2.append(chip("header: " + sc.attribution, "info"));
  if (sc.rate) chips2.append(chip("rate: " + sc.rate));
  if (sc.attribution || sc.rate) scopeCard.append(chips2);
  p.append(scopeCard);
}

function runsTable(rows, id) {
  return mkTable({
    id, defaultSort: { key: "run", dir: -1 },
    cols: [
      { key: "run", label: "run", cls: "num mono", sort: "str" },
      { key: "date", label: "date", cls: "num", sort: "str" },
      { key: "phase", label: "objective", sort: "str", cls: "wrap cellmain" },
      { key: "selector", label: "selector", cls: "wrap dim", sort: "str" },
      { key: "status", label: "status", sort: "str", render: r => runStatusChip(r.status) },
      { key: "result", label: "result", sort: "str", cls: "wrap dim",
        render: r => el("span", { title: (r.limitations || "") + (r.resume_from ? "  · resume: " + r.resume_from : ""), text: r.result || "—" }) },
    ],
    rows: rows.map(r => ({ run: r.run_id, date: r.date, phase: r.phase, selector: r.selector,
      status: r.status, result: (r.result || "").length > 160 ? r.result.slice(0, 159) + "…" : r.result,
      limitations: r.limitations, resume_from: r.resume_from })),
    empty: "No runs recorded yet — kb.py run opens one before every unit that sends traffic.",
  }).wrap;
}

async function tabHosts(p, tg) {
  const name = tg.meta.name;
  p.append(el("div", { cls: "skel" }));
  let d;
  try { d = await api("/api/target/" + encodeURIComponent(name) + "/hosts"); }
  catch (e) { p.textContent = ""; p.append(banner("bad", el("b", { text: "Could not load hosts: " }), String(e.message || e))); return; }
  p.textContent = "";
  const st = d.live_hosts_state || {};
  if (d.vps === "ok") {
    p.append(banner("ok",
      el("b", { text: `${fmt(d.enriched)} of ${fmt(d.total)} host(s) enriched ` }),
      "from the newest VPS httpx artifact (read-only SSH, cached 60s). Local observations take precedence — the artifact fills gaps, never overrides."));
  } else if (d.vps === "not-configured") {
    p.append(banner("warn",
      el("b", { text: "VPS not configured — " }),
      "status/title/tech below come only from the local brain (observations + technologies.md). Set ",
      el("code", { text: "vps.*" }), " in config.json and the console enriches every host live from ",
      el("code", { text: "raw/http" }), " on the VPS."));
  } else if (d.vps) {
    p.append(banner("warn", el("b", { text: "VPS fetch failed — " }), String(d.vps).replace(/^error: /, ""),
      ". Showing local-brain data only."));
  }
  if (st.state === "demoted") {
    p.append(banner("warn", el("b", { text: `live-hosts.txt lives on the VPS (${fmt(st.count)} lines). ` }),
      "This list is built from technologies.md / observations / app brains instead — pull the file with ",
      el("code", { text: "vps-sync.py pull " + name }), " for the full inventory."));
  } else if (st.state === "missing") {
    p.append(banner("warn", el("b", { text: "live-hosts.txt missing — " }),
      el("code", { text: "http-probing" }), " produces it. The list below is what the brain does have."));
  }
  p.append(banner("", el("b", { text: `${fmt(d.rich_local)} of ${fmt(d.total)} host(s) ` }),
    "carry status/tech in the local brain (observations + technologies.md). Per-host status code and title for the full estate live in the httpx artifact on the VPS — they appear here as ",
    el("b", { text: "—" }), " until an observation or app brain records them."));
  p.append(el("div", { cls: "card" }, el("h3", null, "Live hosts",
    el("span", { cls: "right", text: `${fmt(d.total)} host(s) · click a host for its app dashboard` })),
    mkBigTable({
      id: "hosts",
      rows: d.hosts,
      cols: [
        { key: "host", label: "host", cls: "cellmain",
          render: h => hostLink(name, h.host) },
        { key: "status", label: "status", render: h => httpChip(h.status) },
        { key: "title", label: "title", cls: "dim wrap" },
        { key: "tech", label: "technology", cls: "dim wrap" },
        { key: "app", label: "brain", render: h => h.app ? chip("app brain", "acc") : el("span", { cls: "mut2", text: "—" }) },
        { key: "act", label: "activity", cls: "dim", value: h => {
          const a = h.activity || {};
          return [a.runs ? a.runs + " runs" : null, a.probes ? a.probes + " probes" : null,
            a.surface ? a.surface + " surface" : null, a.hypotheses ? a.hypotheses + " hyp" : null]
            .filter(Boolean).join(" · ") || "—";
        } },
      ],
    })));
}

async function tabEndpoints(p, tg) {
  const name = tg.meta.name;
  p.append(el("div", { cls: "skel" }));
  let d;
  try { d = await api("/api/target/" + encodeURIComponent(name) + "/endpoints"); }
  catch (e) { p.textContent = ""; p.append(banner("bad", el("b", { text: "Could not load endpoints: " }), String(e.message || e))); return; }
  p.textContent = "";
  const chips = el("div", { cls: "chips", style: "margin-bottom:12px" });
  for (const [lbl, st] of [["urls.txt", d.urls], ["parameters.txt", d.params]]) {
    if (!st) continue;
    const txt = st.state === "missing" ? lbl + ": missing" : st.state === "demoted" ? `${lbl}: ${fmt(st.count)} on VPS`
      : st.count != null ? `${lbl}: ${fmt(st.count)}` : lbl + ": " + st.state;
    chips.append(chip(txt, st.state === "missing" ? "bad" : st.state === "demoted" ? "warn" : ""));
  }
  p.append(chips);
  if (d.urls && d.urls.state !== "missing" && d.urls.count) {
    p.append(banner("acc", el("b", { text: `${fmt(d.urls.count)} url(s) exist as bulk — ` }),
      "they have not been probed as a set. The unit that does it is ", el("code", { text: "http-probing" }),
      " on the urls artifact (via ", el("code", { text: "vps-run.py" }),
      ", opens a run, attribution injected) — and its output is what fills status/title for them here. A suggestion, not a queue."));
  }
  if (!d.rows.length) {
    p.append(banner("warn", el("b", { text: "endpoints.md is empty. " }),
      "It is the curated interesting slice written by ", el("code", { text: "url-collection" }), " · ",
      el("code", { text: "api-discovery" }), " · ", el("code", { text: "application-mapping" }),
      " — not a dump of every URL. The bulk counts above say what raw material exists."));
    return;
  }
  const hdr = (d.header || []).map(h => h.replace(/[*`]/g, "").trim().toLowerCase());
  const fi = n => hdr.findIndex(h => h.includes(n));
  const I = { url: fi("url"), method: fi("method"), params: fi("params"), auth: fi("auth"),
    ct: fi("content_type"), tech: fi("tech"), why: fi("interesting"), src: fi("source") };
  const get = (r, i) => (i >= 0 && i < r.length ? r[i] : "");
  p.append(el("div", { cls: "card" }, el("h3", null, "Notable endpoints",
    el("span", { cls: "right", text: fmt(d.total) + " row(s) — the interesting slice, not the full URL corpus" })),
    rawTable({
      id: "endpoints", header: d.header, rows: d.rows,
      picks: [
        { i: I.url, label: "url", cls: "mono cellmain wrap" },
        { i: I.method, label: "method" },
        { i: I.params, label: "params", cls: "dim wrap" },
        { i: I.auth, label: "auth", render: r => { const v = get(r, I.auth); return v ? chip(v, /required/i.test(v) ? "warn" : "ok") : el("span", { cls: "mut2", text: "—" }); } },
        { i: I.ct, label: "content-type", cls: "dim" },
        { i: I.tech, label: "tech/app", cls: "dim" },
        { i: I.why, label: "why interesting", cls: "dim wrap" },
      ],
    })));
}

/* ---------------------------------------------------------------- app (per-host) view */
async function renderApp(ap) {
  resetTables();
  const main = $("#main");
  main.textContent = "";
  const name = S.target, host = ap.host;
  main.append(topbar([
    el("a", { href: "#/", text: "Fleet" }), el("span", { text: "/" }),
    el("a", { href: "#/t/" + encodeURIComponent(name), text: name }),
    el("span", { text: "/" }), el("b", { cls: "mono", text: host }),
  ], "filter this host's tables — endpoint, class, tool…"));

  main.append(el("h1", { style: "margin:0 0 4px;font-size:22px", cls: "mono" }, host));
  const hrow = ap.host_row;
  const hchips = el("div", { cls: "chips", style: "margin:6px 0 10px" });
  if (hrow && hrow.status) hchips.append(httpChip(hrow.status));
  if (hrow && hrow.title) hchips.append(chip(hrow.title));
  if (ap.app) hchips.append(chip("application brain", "acc"));
  else hchips.append(chip("no app brain yet", "warn"));
  if (hrow && hrow.tech) hchips.append(chip(hrow.tech, "info"));
  main.append(hchips);

  if (!ap.app) main.append(banner("acc",
    el("b", { text: "No per-application brain exists for this host. " }),
    el("code", { text: "application-mapping" }), " creates ",
    el("code", { text: `applications/${host.replace(":", "-")}/{map,endpoints,notes}.md` }),
    " (via ", el("code", { text: `tools/app-context.py ensure ${name} ${host}` }), ").",
    " Everything below is this host's slice of the target brain."));

  const cards = el("div", { cls: "grid kpis" });
  cards.append(
    kpi({ v: fmt(ap.runs.length), l: "runs touching host", ic: "radar" }),
    kpi({ v: fmt(ap.tested.rows.length), l: "probes logged", ic: "flask" }),
    kpi({ v: fmt(ap.surface.rows.length), l: "surface rows", ic: "target" }),
    kpi({ v: fmt(ap.hypotheses.rows.length), l: "hypotheses", ic: "clock" }),
    kpi({ v: fmt(ap.endpoints.total), l: "app endpoints", ic: "layers", cls: ap.endpoints.total ? "" : "dim" }),
    kpi({ v: ap.urls ? fmt(ap.urls.length) : "—", l: "urls on host", ic: "globe",
      sub: ap.urls ? null : "urls.txt not local", cls: ap.urls ? "" : "dim" }));
  main.append(cards);
  main.append(el("p", { cls: "sub small mut2", id: "qhint", style: "min-height:1.2em;margin:6px 0 0" }));

  const add = (title, node, right) => { main.append(el("div", { cls: "card", style: "margin-top:14px" },
    el("h3", null, title, right ? el("span", { cls: "right", text: right }) : null), node)); };

  if (ap.progress_html) add("Host progress — from progress.md", mdHolder(ap.progress_html));
  if (ap.runs.length) add("Runs touching this host", runsTable(ap.runs, "app-runs"));
  if (ap.map_html) add("Application map", mdHolder(ap.map_html));
  if (ap.tested.rows.length) add("Tested on this host", testedTable(ap.tested.header, ap.tested.rows, "app-tested"),
    "cells are entrypoint × class × principal × variant");
  if (ap.surface.rows.length) add("Surface on this host", surfaceTable(ap.surface.header, ap.surface.rows, "app-surface"));
  if (ap.hypotheses.rows.length) add("Hypotheses mentioning this host", hypTable(ap.hypotheses.header, ap.hypotheses.rows, "app-hyp"));
  if (ap.endpoints.rows.length) {
    const hdr = (ap.endpoints.header || []).map(h => h.replace(/[*`]/g, "").trim().toLowerCase());
    const fi = n => hdr.findIndex(h => h.includes(n));
    add("App endpoints — applications/" + (ap.app ? ap.app.dir : ""), rawTable({
      id: "app-endpoints", header: ap.endpoints.header, rows: ap.endpoints.rows, picks: [
        { i: fi("url"), label: "url", cls: "mono cellmain wrap" },
        { i: fi("method"), label: "method" },
        { i: fi("params"), label: "params", cls: "dim wrap" },
        { i: fi("auth"), label: "auth" },
        { i: fi("why") >= 0 ? fi("why") : fi("notes"), label: "why / notes", cls: "dim wrap" },
      ],
    }), fmt(ap.endpoints.total) + " row(s)");
  }
  if (ap.urls && ap.urls.length) {
    add("URLs on this host — urls.txt slice", mkBigTable({
      id: "app-urls", rows: ap.urls.map(u => ({ url: u })), chunk: 200,
      cols: [{ key: "url", label: "url", cls: "mono cellmain wrap" }],
    }), `showing the local slice (${fmt(ap.urls.length)} capped at 800)`);
  }
  if (ap.observations.length) {
    add("Observations about this host", mkTable({
      id: "app-obs",
      cols: [
        { key: "date", label: "date", cls: "num" },
        { key: "pred", label: "predicate", cls: "cellmain" },
        { key: "obj", label: "observation", cls: "wrap" },
        { key: "src", label: "source", cls: "dim" },
      ],
      rows: ap.observations.map(r => ({ date: r.date, pred: r.predicate, obj: r.object, src: (r.source || "") + " · " + (r.evidence || "") })),
    }).wrap);
  }
  if (ap.notes_html && ap.app) add("App notes", mdHolder(ap.notes_html));
  updateStamp();
}

function mdHolder(html) {
  const holder = document.createElement("div");
  holder.className = "progress-md";
  holder.innerHTML = html;   // backend renders this escaped-first
  return holder;
}

function tabRuns(p, tg) {
  if (tg.open_runs.length) {
    p.append(banner("bad",
      el("i", { cls: "dotp live", style: "color:var(--bad);display:inline-block" }),
      el("b", { text: ` ${tg.open_runs.length} run(s) left RUNNING — ` }),
      "traffic may already have been sent. Check the VPS before re-running."));
    p.append(el("div", { cls: "card" }, el("h3", null, "Currently running"), runsTable(tg.open_runs, "open-runs")));
  } else {
    p.append(banner("ok", el("b", { text: "No unfinished work. " }), "Every run was closed."));
  }
  if (tg.resume.length) {
    p.append(banner("warn", el("b", { text: `${tg.resume.length} resume point(s) ` }),
      "— a partial or failed run that recorded where to continue."));
    p.append(el("div", { cls: "card" }, el("h3", null, "Resume points"), runsTable(tg.resume, "resume")));
  }
  p.append(el("div", { cls: "card" }, el("h3", null, "Run ledger",
    el("span", { cls: "right", text: `showing ${Math.min(tg.runs.length, 300)} of ${tg.runs_total} — kb.py runs for the full ledger` })),
    runsTable(tg.runs, "ledger")));
}

function hdrIdx(header) {
  const hdr = (header || []).map(h => h.replace(/[*`]/g, "").trim().toLowerCase());
  const fi = pred => hdr.findIndex(pred);
  return { hdr, fi };
}

function surfaceTable(header, rows, id) {
  const { fi } = hdrIdx(header);
  const iRank = fi(h => h.startsWith("rank")), iScore = fi(h => h.includes("score")),
    iEp = fi(h => h.includes("entrypoint")), iClass = fi(h => h.includes("class")),
    iVar = fi(h => h.startsWith("variant")), iProp = fi(h => h.startsWith("propert")),
    iWhy = fi(h => h.startsWith("why"));
  const maxScore = Math.max(...rows.map(r => num(r[iScore])));
  const get = (r, i) => (i >= 0 && i < r.length ? r[i] : "");
  return mkTable({
    id,
    defaultSort: iRank >= 0 ? { key: "rank", dir: 1 } : null,
    cols: [
      { key: "rank", label: "rank", cls: "num", num: true, value: r => get(r, iRank) },
      { key: "score", label: "score", num: true, value: r => get(r, iScore),
        render: r => { const v = get(r, iScore); return el("span", null,
          el("span", { cls: "mini-bar", style: `width:${clampBar(num(v), maxScore)}px` }), v || "—"); } },
      { key: "entrypoint", label: "entrypoint", cls: "wrap mono cellmain", value: r => get(r, iEp) },
      { key: "class", label: "class", value: r => get(r, iClass),
        render: r => chip(get(r, iClass), "acc") },
      { key: "variants", label: "variants", cls: "dim", value: r => get(r, iVar) },
      { key: "properties", label: "properties", cls: "dim", value: r => get(r, iProp) },
      { key: "why", label: "why (source→sink)", cls: "wrap dim", value: r => get(r, iWhy) },
    ],
    rows,
  }).wrap;
}

function hypTable(header, rows, id) {
  const { fi } = hdrIdx(header);
  const I = { id: fi(h => h.startsWith("id")), target: fi(h => h.includes("target")),
    cls: fi(h => h.includes("class")), why: fi(h => h.includes("rationale")),
    st: fi(h => h.startsWith("status")), ev: fi(h => h.includes("evidence")) };
  const get = (r, i) => (i >= 0 && i < r.length ? r[i] : "");
  return mkTable({
    id,
    cols: [
      { key: "id", label: "id", cls: "mono", value: r => get(r, I.id) },
      { key: "target", label: "target", cls: "wrap cellmain", value: r => get(r, I.target) },
      { key: "class", label: "class", value: r => get(r, I.cls) },
      { key: "why", label: "rationale", cls: "wrap dim", value: r => get(r, I.why) },
      { key: "st", label: "status", value: r => get(r, I.st),
        render: r => hypChip(get(r, I.st).split(" ")[0].toLowerCase()) },
      { key: "ev", label: "evidence", cls: "mono dim", value: r => get(r, I.ev) },
    ],
    rows,
  }).wrap;
}

function testedTable(header, rows, id) {
  const { fi } = hdrIdx(header);
  const I = { date: fi(h => h.startsWith("date")), run: fi(h => h.startsWith("run")),
    ep: fi(h => h.includes("entrypoint")), cls: fi(h => h.includes("class")),
    variant: fi(h => h.startsWith("variant")), res: fi(h => h.startsWith("result")),
    cov: fi(h => h.startsWith("coverage")), art: fi(h => h.includes("artifact")) };
  const get = (r, i) => (i >= 0 && i < r.length ? r[i] : "");
  return mkTable({
    id,
    cols: [
      { key: "date", label: "date", cls: "num", value: r => get(r, I.date) },
      { key: "run", label: "run", cls: "mono", value: r => get(r, I.run) },
      { key: "ep", label: "entrypoint / variant", cls: "wrap mono cellmain",
        value: r => get(r, I.ep) + (get(r, I.variant) ? "  [" + get(r, I.variant) + "]" : "") },
      { key: "cls", label: "class", value: r => get(r, I.cls) },
      { key: "res", label: "result", value: r => get(r, I.res),
        render: r => { const v = get(r, I.res); return chip(v, v === "vuln" ? "bad" : v === "not-vuln" ? "ok" : v === "inconclusive" ? "warn" : ""); } },
      { key: "cov", label: "coverage", cls: "dim", value: r => get(r, I.cov),
        render: r => { const v = get(r, I.cov); return chip(v, v === "tested" ? "ok" : v === "blocked" ? "bad" : "warn"); } },
      { key: "art", label: "evidence", cls: "mono dim", value: r => get(r, I.art) },
    ],
    rows,
  }).wrap;
}

function tabSurface(p, tg) {
  if (!tg.surface.rows.length) {
    p.append(banner("bad", el("b", { text: "No ranked surface. " }),
      "derive-properties / attack-surface-prioritization have not produced rows, so any model-chosen test would be picking by whatever it happened to notice."));
    return;
  }
  p.append(el("div", { cls: "card" }, el("h3", null, "Attack surface",
    el("span", { cls: "right", text: `${tg.surface.total} (entrypoint × class) row(s)` })),
    surfaceTable(tg.surface.header, tg.surface.rows, "surface")));
}

function tabBacklog(p, tg) {
  const hyp = tg.hypotheses;
  if (hyp.rows.length) {
    p.append(el("div", { cls: "card" }, el("h3", null, "Hypotheses — the testing backlog"),
      hypTable(hyp.header, hyp.rows, "hyp")));
  } else {
    p.append(banner("ok", el("b", { text: "Hypotheses empty. " }),
      "Rows appear when recon properties imply a class worth naming."));
  }
  const kinds = [["confirmed", "ok"], ["draft", "warn"], ["rejected", "mut"]];
  const grid = el("div", { cls: "grid", style: "grid-template-columns:repeat(auto-fit,minmax(240px,1fr))" });
  for (const [kind, cls] of kinds) {
    const list = tg.findings[kind] || [];
    grid.append(el("div", { cls: "card" },
      el("h3", null, kind, el("span", { cls: "right", text: fmt(list.length) })),
      list.length
        ? el("ul", { style: "margin:0;padding-left:18px" }, ...list.map(f => el("li", { cls: "mono small", text: f })))
        : el("div", { cls: "empty" }, "none")));
  }
  p.append(grid);
}

function tabLogs(p, tg) {
  if (tg.log_failures) {
    p.append(banner("warn",
      el("b", { text: `${tg.log_failures} tool invocation(s) exited non-zero. ` }),
      "Whatever depended on them may have been written anyway — tools/runlog.py <t> --failures."));
  }
  p.append(el("div", { cls: "card" }, el("h3", null, "Tool invocation log",
    el("span", { cls: "right", text: `newest ${tg.logs.length} — logs/tools.tsv` })),
    mkTable({
      id: "logs",
      cols: [
        { key: "ts", label: "when", cls: "num mono", sort: "str" },
        { key: "tool", label: "tool", cls: "mono cellmain", sort: "str" },
        { key: "exit", label: "exit", cls: "num", sort: "str",
          render: r => r.exit === "0" ? chip("0", "ok") : r.exit === "" ? chip("—", "") : chip(r.exit, "bad") },
        { key: "argv", label: "command (redacted)", cls: "wrap mono dim", sort: "str" },
      ],
      rows: tg.logs.map(r => ({ ts: (r.ts || "").slice(0, 19).replace("T", " "), tool: r.tool, exit: r.exit,
        argv: (r.argv || "").slice(0, 220) })),
      empty: "No tool invocations recorded yet — run.py/vps-run.py append here.",
    }).wrap));
}

async function tabVps(p, tg) {
  const name = tg.meta.name;
  p.append(el("div", { cls: "skel" }));
  let d;
  try { d = await api("/api/target/" + encodeURIComponent(name) + "/vps"); }
  catch (e) { p.textContent = ""; p.append(banner("bad", el("b", { text: "Could not load: " }), String(e.message || e))); return; }
  p.textContent = "";
  const inv = d.inventory || {}, mon = d.monitor || {};
  if (inv.error === "not-configured") {
    p.append(banner("warn", el("b", { text: "VPS not configured. " }),
      "This tab lists the raw artifacts on the VPS (", el("code", { text: "raw/*" }),
      ") and pending monitor deltas, fetched read-only over SSH. Set ", el("code", { text: "vps.*" }),
      " in config.json (see ", el("code", { text: "playbooks/system/vps-setup.md" }), ") to switch it on."));
    return;
  }
  if (inv.error) p.append(banner("warn", el("b", { text: "Inventory fetch failed — " }), inv.error));
  if (mon.error) p.append(banner("warn", el("b", { text: "Monitor fetch failed — " }), mon.error));

  // monitor deltas first: they are the thing waiting for a human decision
  if (mon.markdown) {
    p.append(el("div", { cls: "card" }, el("h3", null, "Pending monitor deltas",
      el("span", { cls: "right", text: "reconcile with tools/monitor.py pending " + name })),
      el("div", { cls: "small mut", style: "white-space:pre-wrap;font-family:var(--mono);overflow-x:auto", text: mon.markdown })));
  } else if (!mon.error) {
    p.append(banner("ok", el("b", { text: "No pending monitor deltas. " },
      "Everything the scheduled job found has been reviewed (or no monitor is enabled).")));
  }

  const files = inv.files || [];
  if (files.length) {
    const byDir = {};
    for (const f of files) (byDir[f.dir] = byDir[f.dir] || []).push(f);
    const total = files.reduce((a, f) => a + f.size, 0);
    p.append(el("div", { cls: "card" }, el("h3", null, "Raw artifacts on the VPS",
      el("span", { cls: "right", text: `${fmt(files.length)} file(s) · ${nfmt(total)} B` })),
      mkTable({
        id: "vps-inv",
        cols: [
          { key: "dir", label: "phase dir", cls: "mono cellmain", sort: "str" },
          { key: "file", label: "artifact", cls: "mono wrap" },
          { key: "size", label: "size", cls: "num", num: true, render: f => nfmt(f.size) + " B" },
          { key: "date", label: "date", cls: "num", sort: "str" },
        ],
        rows: files,
      }).wrap,
      el("p", { cls: "small mut2", style: "margin:8px 0 0" },
        "Bulk stays on the VPS by design — ", el("code", { text: "vps-sync.py pull " + name }),
        " brings one artifact's extract into the brain when a unit needs it.")));
  } else if (!inv.error) {
    p.append(banner("", el("b", { text: "No raw artifacts yet. " },
      "Recon phases write to raw/ on the VPS as they run.")));
  }
}

function tabProgress(p, tg) {
  if (!tg.progress_html) {
    p.append(banner("warn", el("b", { text: "progress.md not generated yet. " }),
      "Run tools/progress.py targets/<t> after a unit of work."));
    return;
  }
  const card = el("div", { cls: "card progress-md" });
  const holder = document.createElement("div");
  holder.innerHTML = tg.progress_html;   // backend renders this escaped-first
  card.append(holder);
  p.append(card);
}

function tabFiles(p, tg) {
  p.append(banner("", "Bulk raw output lives on the VPS and is not counted here. ",
    el("b", { text: "accounts.md " }), "is summarized (usable principals), never rendered."));
  p.append(el("div", { cls: "card" }, el("h3", null, "Brain files — state and age"),
    mkTable({
      id: "files",
      cols: [
        { key: "file", label: "file", cls: "mono cellmain", sort: "str" },
        { key: "state", label: "state", sort: "str", render: r => {
          const s = r.state;
          const cls = s === "missing" ? "bad" : s === "empty" ? "" : s === "demoted" ? "warn" : "ok";
          const lbl = { missing: "missing", empty: "0", prose: "prose", demoted: "on VPS",
            lines: "lines", rows: "rows" }[s] || s;
          return chip(lbl, cls, s);
        } },
        { key: "count", label: "rows/lines", cls: "num", num: true, render: r => fmt(r.count) },
        { key: "age", label: "age", cls: "num", num: true, render: r => r.age_days == null ? "—" : r.age_days === 0 ? "today" : r.age_days + "d" },
      ],
      rows: tg.files,
    }).wrap));
}

/* ---------------------------------------------------------------- router */
function parseHash() {
  const h = decodeURIComponent(location.hash || "");
  if (!h || h === "#/" || h === "#") return { view: "fleet" };
  let m = h.match(/^#\/t\/([^/]+)\/app\/(.+)$/);
  if (m) return { view: "app", name: m[1], host: m[2] };
  m = h.match(/^#\/t\/([^/]+)(?:\/(\w+))?/);
  if (m) return { view: "target", name: m[1], tab: TABS.includes(m[2]) ? m[2] : "overview" };
  return { view: "fleet" };
}

async function route() {
  const r = parseHash();
  S.view = r.view; S.target = r.name || null; S.tab = r.tab || "overview"; S.appHost = r.host || null;
  renderSide(S.ov);
  $("#main").textContent = "";
  $("#main").append(el("div", { cls: "skel" }));
  try {
    if (S.view === "fleet") {
      S.ov = await api("/api/overview");
      S.loadedAt = new Date().toISOString();
      renderSide(S.ov);
      renderFleet(S.ov);
    } else if (S.view === "app") {
      S.tg = null;
      S.ap = await api("/api/target/" + encodeURIComponent(S.target) + "/app/" + encodeURIComponent(S.appHost));
      S.loadedAt = new Date().toISOString();
      S.ov = S.ov || await api("/api/overview");
      renderSide(S.ov);
      renderApp(S.ap);
    } else {
      S.ap = null;
      S.tg = await api("/api/target/" + encodeURIComponent(S.target));
      S.loadedAt = new Date().toISOString();
      S.ov = S.ov || await api("/api/overview");
      renderSide(S.ov);
      renderTarget(S.tg);
    }
  } catch (e) {
    const main = $("#main");
    main.textContent = "";
    main.append(banner("bad", el("b", { text: "Could not load: " }), String(e.message || e)),
      el("p", { cls: "mut" }, "Is tools/dashboard-server.py running? Try ", el("code", { text: "tools/dashboard-server.py" }), "."));
  }
}

async function refresh() {
  if (document.hidden) return;
  const y = window.scrollY;
  const q = $("#q") ? $("#q").value : "";
  try {
    if (S.view === "fleet") {
      const ov = await api("/api/overview");
      S.ov = ov; S.loadedAt = new Date().toISOString(); renderFleet(ov);
    } else if (S.view === "app") {
      const ap = await api("/api/target/" + encodeURIComponent(S.target) + "/app/" + encodeURIComponent(S.appHost));
      S.ap = ap; S.loadedAt = new Date().toISOString(); renderApp(ap);
    } else {
      const tg = await api("/api/target/" + encodeURIComponent(S.target));
      S.tg = tg; S.loadedAt = new Date().toISOString(); renderTarget(tg);
    }
    if (q && $("#q")) { $("#q").value = q; applyFilter(q); }
    window.scrollTo(0, y);
  } catch (_) { /* transient — the next tick retries */ }
}

function updateStamp() {
  const u = $("#updated");
  if (u && S.loadedAt) u.textContent = "updated " + ago(S.loadedAt);
}

/* ---------------------------------------------------------------- boot */
document.addEventListener("keydown", e => {
  if (e.key === "/" && !/input|textarea/i.test(document.activeElement.tagName)) {
    const q = $("#q");
    if (q) { e.preventDefault(); q.focus(); }
  }
});
window.addEventListener("hashchange", route);
setInterval(refresh, 15000);
setInterval(updateStamp, 5000);

(async function boot() {
  renderShell();
  try {
    const [ov, vps] = await Promise.all([
      api("/api/overview"),
      api("/api/vps").catch(() => null),
    ]);
    S.ov = ov;
    S.vps = vps ? vps.state : null;
    S.loadedAt = new Date().toISOString();
  } catch (_) {}
  route();
})();
