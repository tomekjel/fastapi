"""Shared owner-only Multi-Servis web design tokens and responsive V12 family styling.

One single OWNER interface. Crimson from Multi-Guard Standard and brushed gold
from Multi-Guard Pro are visual DNA, *not* different owner panel editions.
Keep body text >= 15px, weights <= 500 and feature-specific layouts.
"""

PANEL_CSS = r"""
:root {
  color-scheme: dark;
  --bg: #07101d;
  --rail: #0c1727;
  --surface: #111f30;
  --surface-raised: #17293b;
  --surface-soft: #101b2b;
  --line: rgba(154, 176, 196, .19);
  --line-light: rgba(195, 208, 221, .25);
  --gold: #e6bc65;
  --gold-low: rgba(230,188,101,.12);
  --crimson: #ed4056;
  --crimson-low: rgba(237,64,86,.12);
  --cyan: #9bc9d9;
  --text: #e9eef4;
  --muted: #b0bfce;
  --subtle: #91a5b8;
  --green: #77cfa6;
  --focus: #e6bc65;
  font: 400 16px/1.55 "Segoe UI Variable", "Segoe UI", system-ui, sans-serif;
  background: var(--bg);
  color: var(--text);
}
* { box-sizing: border-box }
html { scroll-behavior: smooth }
body { margin: 0; min-height: 100vh; background:
  radial-gradient(ellipse 65% 50% at 92% 2%, rgba(41,90,145,.12), transparent 65%),
  linear-gradient(145deg,#07101e,#080f1a 75%) }
body, input, select, textarea, button { font-weight: 400 }
a { color: var(--cyan); text-underline-offset: 4px }
a:hover { color: #f0d9ad }
a:focus-visible,button:focus-visible,input:focus-visible,
select:focus-visible,textarea:focus-visible { outline: 2px solid var(--focus); outline-offset: 3px }
h1,h2,h3,p { margin-top: 0 }
h1 { font-size: clamp(28px,2.5vw,39px); line-height: 1.22; font-weight: 400; letter-spacing: -.025em; color: #f7f8fa }
h2 { font-size: clamp(20px,1.7vw,26px); line-height: 1.32; font-weight: 400; letter-spacing: -.016em }
h3 { font-size: 19px; font-weight: 400 }
p { margin-bottom: 14px; color: var(--muted); line-height: 1.65 }
b,strong,th { font-weight: 500 }
small, .muted, .row-sub { color: var(--subtle); font-size: 14px; line-height: 1.5 }
.mono { font-family: "Cascadia Code",Consolas,monospace; font-variant-numeric: tabular-nums; font-size: .95em }
.numbers { white-space: nowrap; font-variant-numeric: tabular-nums }
.ok,.good { color: var(--green) }
.warn { color: var(--gold) }
.bad,.critical { color: #f0a0a8 }
.workspace-shell { display: grid; grid-template-columns: 254px minmax(0,1fr); min-height: 100vh }
.workspace-sidebar { position: sticky; top: 0; height: 100vh; overflow-y: auto;
  background: linear-gradient(170deg,#101e30,#0a1626 65%,#0b1422);
  border-right: 1px solid var(--line); padding: 30px 16px 22px; display: flex; flex-direction: column }
.workspace-sidebar:before { content:""; position:absolute;left:0;top:0;bottom:0;width:2px;
  background:linear-gradient(180deg,var(--crimson),rgba(237,64,86,.2) 45%,transparent 92%);opacity:.8 }
.brand-home { text-decoration: none; color: inherit; display:flex;align-items:center;gap:12px;padding:6px 9px 30px }
.brand-home:hover { color:inherit }
.brand-emblem { flex:none;display:grid;place-items:center;width:43px;height:43px;border-radius:12px;
  border:1px solid rgba(237,64,86,.43);color:var(--crimson);font-size:22px;
  font-weight:400;letter-spacing:-.08em;
  background:radial-gradient(circle at 35% 25%,rgba(237,64,86,.1),transparent 70%),#14253a;
  box-shadow:inset 0 1px rgba(255,255,255,.12),0 3px 14px rgba(0,0,0,.18) }
.brand-name { font-size:20px; letter-spacing:.015em;line-height:1.1;color:#e9edf3;white-space:nowrap }
.brand-multi {color:#ed4056}
.brand-servis {color:#e6bc65}
.brand-caption { font-size:12px; color:var(--subtle);letter-spacing:.07em;display:block;margin-top:5px }
.nav-group-label { margin:0 13px 12px;color:#a9b6c4;font-size:12px;letter-spacing:.12em;text-transform:uppercase }
nav { display:flex;flex-direction:column;gap:4px; margin:0 0 23px;padding:0;position:static }
nav a { display:flex;align-items:center;gap:12px;text-decoration:none;color:#c5d2df;
  border:1px solid transparent;border-radius:10px;padding:11px 12px;
  min-height:45px;font-size:15px;letter-spacing:0; transition:background .16s,border-color .16s }
nav a:hover { color:#f2f6fa;background:rgba(190,204,222,.07);border-color:rgba(190,204,222,.12) }
nav a[aria-current="page"] {color:#f5f8fd; background:#172c42;
  border-color:rgba(237,64,86,.43); box-shadow:inset 3px 0 var(--crimson) }
.nav-icon { width:21px;height:21px; flex:none;display:grid;place-items:center;color:#9eb2c6;font-size:19px;font-weight:400 }
nav a[aria-current="page"] .nav-icon { color:var(--crimson) }
.rail-bottom { margin-top:auto;border-top:1px solid var(--line);padding:19px 12px 0 }
.rail-editions {display:flex;align-items:center;gap:9px; font-size:13px;color:#b5c3d0;letter-spacing:.02em}
.rail-editions:before,.rail-editions:after {content:"";display:block;width:17px;height:2px;border-radius:2px}
.rail-editions:before {background:var(--crimson);box-shadow:0 0 9px rgba(205,120,131,.35)}
.rail-editions:after {background:var(--gold);box-shadow:0 0 9px rgba(216,186,138,.35)}
.rail-bottom p {font-size:13px;margin:9px 0 0;color:#8295aa}
.workspace-content { min-width:0 }
.workspace-topbar {display:flex;align-items:center;justify-content:space-between;gap:20px;
  border-bottom:1px solid var(--line);padding:22px clamp(20px,3vw,42px);
  background:linear-gradient(90deg,rgba(16,30,47,.76),rgba(13,23,38,.28))}
.topbar-kicker {display:block;color:#e8bb69;letter-spacing:.14em;font-size:12px;margin-bottom:3px}
.topbar-title {font-size:18px; color:#e3ebf2; letter-spacing:.01em}
.topbar-owner {display:inline-flex;align-items:center;gap:9px;border:1px solid var(--line);
  border-radius:40px;padding:7px 14px;color:#c3d0da;background:rgba(255,255,255,.025);font-size:13px;white-space:nowrap}
.topbar-owner:before {content:"";width:7px;height:7px;border-radius:50%;background:var(--gold)}
main {width:min(1580px,100%);margin:0 auto;padding:30px clamp(20px,3vw,42px) 64px;min-width:0}
.card {position:relative;min-width:0;overflow:hidden;
  background:linear-gradient(155deg,rgba(26,44,63,.89),rgba(13,26,42,.98));
  border:1px solid var(--line);border-radius:17px;
  padding:25px clamp(20px,2vw,29px);margin-bottom:20px;
  box-shadow:0 12px 35px rgba(2,6,13,.17),inset 0 1px rgba(242,247,255,.065)}
.card:before {content:"";position:absolute;left:26px;right:26px;top:0;height:1px;pointer-events:none;
  background:linear-gradient(90deg,transparent,rgba(130,172,212,.23),transparent)}
.card.panel-hero {border-color:rgba(117,155,196,.31);padding:34px clamp(24px,3vw,38px);
  background:radial-gradient(ellipse at 95% 0%,rgba(54,105,167,.14),transparent 52%),
  linear-gradient(115deg,#172b41,#102137 70%,#0d1e31)}
.card.panel-hero h1 {max-width:840px}
.card.panel-hero p {max-width:890px;margin-bottom:0}
.eyebrow {font-size:13px;letter-spacing:.12em;color:var(--gold);font-weight:400;margin-bottom:12px}
.section-head {display:flex;align-items:center;justify-content:space-between;flex-wrap:wrap;gap:18px;margin-bottom:17px}
.section-head p {margin-bottom:0}
.grid {display:grid;grid-template-columns:2fr 1fr 1fr;gap:16px}
.metrics {display:grid;grid-template-columns:repeat(auto-fit,minmax(175px,1fr));gap:12px;margin-top:20px}
.metric {display:block;min-width:0;min-height:114px;
  padding:20px;border-radius:14px;border:1px solid var(--line);
  background:linear-gradient(145deg,rgba(38,58,76,.57),rgba(13,28,45,.77));
  box-shadow:inset 0 1px rgba(255,255,255,.05)}
.metric b {display:block;font-size:14px;color:#bac6d1;margin-bottom:10px;font-weight:400}
.metric strong {display:block;font-size:clamp(27px,2.6vw,34px);line-height:1.17;
  font-weight:400;color:#f4f6fa;font-variant-numeric:tabular-nums}
.metric small {display:block;color:#9fb2c5;font-size:13px;margin-top:8px}
.metric .money {font-size:clamp(20px,2.25vw,29px);overflow-wrap:anywhere}
.metric-link {text-decoration:none;color:inherit;transition:transform .16s,border-color .16s}
.metric-link:hover {transform:translateY(-2px);border-color:rgba(230,188,101,.4);color:inherit}
.accent-blue {border-left:2px solid var(--cyan)}
.accent-gold {border-left:2px solid var(--gold)}
.accent-green {border-left:2px solid var(--green)}
.accent-red {border-left:2px solid var(--crimson)}
/* Overview: broad operational summary, not repeated shield widgets */
.dashboard-hero {display:grid;gap:7px}
.dashboard-hero .metrics {grid-template-columns:repeat(auto-fit,minmax(156px,1fr))}
.dashboard-hero .metric {background:rgba(10,24,39,.45)}

/* OWNER landing hub and separate inventory: purposeful, non-repeated layouts */
.hub-grid {display:grid;grid-template-columns:repeat(2,minmax(0,1fr));gap:15px;margin-top:20px}
.hub-tile {display:grid;align-content:start;gap:7px;min-height:170px;padding:22px;
  background:#102337;border:1px solid rgba(112,154,194,.28);border-radius:14px;
  color:var(--text);text-decoration:none;transition:background .18s,border-color .18s,transform .18s}
.hub-tile:hover {background:#172e46;border-color:rgba(237,64,86,.55);color:var(--text);transform:translateY(-2px)}
.hub-tile strong {font-size:21px;font-weight:400;color:#f4f7fb}
.hub-tile>span:not(.hub-symbol) {color:var(--muted);font-size:15px}
.hub-tile small {color:var(--gold);font-size:14px;margin-top:8px}
.hub-symbol {font-size:27px;color:var(--crimson);line-height:1.1}
.summary-footnote .section-head {margin-bottom:5px}
.computers-hero {border-left:3px solid #598ab8!important}
.inventory-headline {display:flex;gap:13px;align-items:center;flex-wrap:wrap;margin-top:18px}
.inventory-headline .muted {font-size:14px}

/* Service: records-first, operational data needs its own rhythm */
.service-hero {background:linear-gradient(125deg,#203044,#14263c 62%,#152130)}
.service-hero .owner-kpis {grid-template-columns:repeat(auto-fit,minmax(184px,1fr))}
.service-hero .metric {border-top:2px solid rgba(94,156,217,.38)}
/* Telemetry: subdued cool diagnostics, severity colors only for findings */
.telemetry-hero {border-color:rgba(148,193,213,.28)!important;
  background:radial-gradient(ellipse at 90% 10%,rgba(92,146,186,.12),transparent 55%),linear-gradient(125deg,#172c3e,#101e32)!important}
.telemetry-status {display:flex;flex-direction:column;gap:8px;align-items:flex-end}
/* Device: physical asset profile with related orders */
.device-hero {border-left:3px solid var(--gold)}
.device-timeline {border-left:1px solid rgba(216,186,138,.24);padding-left:21px}
/* Licenses: one owner console, Standard/Pro only on asset entitlement badges */
.license-hero {border-top:2px solid rgba(216,186,138,.42)}
.license-hero .detail-facts {max-width:1200px}
/* History: restrained release chronology, not metric blocks */
.release-timeline {display:grid;gap:15px;margin-top:22px}
.release-card {position:relative;background:linear-gradient(135deg,#182a3d,#101f31);
  padding:24px 24px 24px 32px;border:1px solid var(--line);border-radius:13px}
.release-card:before {content:"";position:absolute;left:0;top:19px;bottom:19px;width:2px;background:var(--gold)}
.release-card .section-head {margin-bottom:7px}
.release-card .eyebrow {margin-bottom:5px}
.release-changes {list-style:disc;margin:16px 0 0;padding-left:24px;color:#cbd6e1;line-height:1.9}
.release-changes .badge {margin-right:8px;min-width:102px;text-align:center}
.table-wrap {width:100%;overflow-x:auto;overscroll-behavior-x:contain;
  border:1px solid var(--line);border-radius:12px;background:rgba(6,16,28,.46)}
table {width:100%;border-collapse:collapse;min-width:840px;font-size:15px}
th,td {text-align:left;vertical-align:middle;padding:14px 15px;border-bottom:1px solid rgba(143,168,191,.12)}
th {position:sticky;top:0;background:#1b2e42;color:#c9d6e4;font-size:13px;letter-spacing:.04em;
  font-weight:400;text-transform:uppercase;white-space:nowrap;z-index:1}
td {color:#dce6ef;line-height:1.5}
td b,td strong {font-weight:400;color:#f0f4f8}
tr:hover td {background:rgba(159,194,219,.043)}
tbody tr:last-child td {border-bottom:0}
.telemetry-table td {vertical-align:middle}
.media-thumb {display:block;max-width:115px;width:115px;height:76px;object-fit:cover;
  border:1px solid var(--line-light);border-radius:8px;background:#0b1d2b;
  transition:border-color .15s,transform .15s}
a:hover .media-thumb {border-color:var(--gold);transform:scale(1.02)}


/* Owner photo viewer: next / previous without opening new browser tabs */
.photo-viewer {width:min(1200px,96vw);max-width:96vw;max-height:95vh;overflow:hidden;
  padding:0;border-radius:15px;border:1px solid #527395;background:#091523;color:var(--text);
  box-shadow:0 35px 100px rgba(0,0,0,.72)}
.photo-viewer::backdrop {background:rgba(0,5,13,.9);backdrop-filter:blur(8px)}
.photo-viewer[open] {display:flex;flex-direction:column}
.viewer-top,.viewer-bottom {display:flex;align-items:center;gap:16px;padding:13px 19px;background:#102134}
.viewer-top {justify-content:space-between;border-bottom:1px solid var(--line)}
.viewer-top strong {font-weight:400;font-size:18px}
.viewer-top button,.viewer-bottom button {min-height:37px;padding:8px 13px}
.viewer-body {display:grid;grid-template-columns:55px minmax(0,1fr) 55px;
  align-items:stretch;min-height:260px;max-height:72vh;background:#050c15}
.viewer-arrow {background:#102134;border:none;border-radius:0;font-size:28px;color:#e8bc65;padding:0;min-width:0}
.viewer-viewport {display:flex;align-items:center;justify-content:center;overflow:auto;min-height:260px;
  max-height:72vh;overscroll-behavior:contain;touch-action:pan-y pan-x}
.viewer-image {display:block;width:100%;max-width:none;max-height:68vh;height:auto;
  object-fit:contain;flex-shrink:0;user-select:none}
.viewer-bottom {flex-wrap:wrap;justify-content:space-between;border-top:1px solid var(--line)}
.viewer-count {font-size:16px;color:var(--gold);white-space:nowrap}
.viewer-caption {flex:1 1 170px;color:#d5e1ed;overflow-wrap:anywhere}
.viewer-zoom {display:flex;align-items:center;gap:8px;flex-shrink:0}
.viewer-zoom-label {min-width:58px;text-align:center;font-size:15px}
.viewer-hint {font-size:13px;margin:0;padding:9px 19px 12px;background:#102134;color:#a1b7c9}
@media(max-width:600px) {
  .photo-viewer {width:100vw;max-width:100vw;max-height:100dvh;border-radius:0}
  .viewer-body {grid-template-columns:37px minmax(0,1fr) 37px;max-height:70dvh}
  .viewer-viewport {max-height:70dvh}
  .viewer-arrow {font-size:22px}
  .viewer-top,.viewer-bottom {padding:10px 12px;gap:9px}
  .viewer-hint {padding:7px 12px;font-size:12px}
}

.problem-title {font-size:16px;color:#e9eff6}
.badge {display:inline-block;max-width:100%;vertical-align:middle;
  color:#bddcee;background:rgba(82,140,172,.11);
  border:1px solid rgba(110,166,196,.36);border-radius:7px;
  font-weight:400;font-size:13px;padding:5px 9px;line-height:1.3}
.badge.good,.badge.mg-green {color:#a8e0c3;border-color:rgba(98,169,130,.38);background:rgba(98,169,130,.085)}
.badge.warn,.badge.mg-gold {color:#e8c797;border-color:rgba(216,186,138,.42);background:var(--gold-low)}
.badge.bad,.badge.critical,.badge.mg-red {color:#efb3b9;border-color:rgba(237,64,86,.47);background:var(--crimson-low)}
.badge.mg-blue {color:#a8d3e4;border-color:rgba(126,183,209,.38)}
.presence-label {display:inline-flex;align-items:center;gap:9px;color:#cdd9e5;font-size:14px;line-height:1.5}
.presence-dot {display:inline-block;width:9px;height:9px;border-radius:50%;background:#6c8499;flex:none}
.presence-recent {background:#6ed8a1;box-shadow:0 0 9px rgba(110,216,161,.34)}
.presence-delayed {background:#dbc08b;box-shadow:0 0 8px rgba(219,192,139,.24)}
.presence-stale,.presence-unknown {background:#7890a6}
.presence-removed {background:#687587;opacity:.65}
.strong-link {color:#e0c18f;text-decoration:none;font-weight:400}
.strong-link:hover {text-decoration:underline}
.button-link, button {display:inline-flex;align-items:center;justify-content:center;
  gap:8px;padding:11px 17px;min-height:44px;
  background:linear-gradient(120deg,#2c4459,#24384f);color:#f2f3f4;
  border:1px solid rgba(171,193,210,.32);border-radius:10px;
  text-decoration:none;letter-spacing:.025em;font:400 15px/1.2 "Segoe UI Variable","Segoe UI",sans-serif;
  cursor:pointer;transition:filter .15s,border-color .15s}
button {border-color:rgba(237,64,86,.38);background:linear-gradient(115deg,#832638,#611d2d)}
.button-link:hover,button:hover {filter:brightness(1.15);border-color:var(--crimson);color:#fff}
.button-link.compact {padding:9px 11px;min-height:37px;font-size:14px;white-space:nowrap}
form {display:grid;gap:16px}
label {display:grid;gap:7px;font-size:15px;color:#c9d6e2}
input,select,textarea {font:400 16px/1.4 "Segoe UI Variable","Segoe UI",sans-serif;
  width:100%;min-width:0;min-height:45px;padding:11px 13px;color:#eff4f7;
  background:#0a1b2c;border:1px solid rgba(142,171,198,.41);border-radius:9px}
input::placeholder,textarea::placeholder {color:#8095a9;opacity:1}
textarea {min-height:110px;resize:vertical}
input[type=hidden] {display:none}
.filter-tabs {display:flex;gap:9px;flex-wrap:wrap;margin:17px 0}
.filter-tab {color:#b9cddd;font-size:14px;text-decoration:none;padding:9px 13px;
  background:rgba(25,42,59,.65);border:1px solid var(--line);border-radius:9px}
.filter-tab:hover {border-color:rgba(216,186,138,.45)}
.filter-tab.selected {color:#f2f6fd;border-color:rgba(237,64,86,.48);background:rgba(237,64,86,.12)}
.filter-bar {display:flex;flex-wrap:wrap;align-items:end;gap:12px}
.filter-bar label {min-width:175px}
.filter-bar .filter-grow {flex:1 1 320px}
.service-search {display:flex;align-items:end;flex-wrap:wrap;gap:12px;margin:0 0 18px}
.service-search label {flex:1 1 340px}
.pagination {display:flex;justify-content:flex-end;align-items:center;gap:14px;padding:19px 0 0;color:var(--muted);font-size:14px}
.detail-grid,.detail-facts {display:grid;grid-template-columns:repeat(auto-fit,minmax(194px,1fr));gap:12px;margin-top:20px}
.detail-grid>div,.detail-fact,.detail-note {border:1px solid var(--line);border-radius:11px;
  min-width:0;overflow-wrap:anywhere;padding:15px 17px;background:rgba(10,26,42,.56)}
.detail-grid b,.detail-fact b,.detail-fact span {display:block}
.detail-grid b,.detail-fact b {color:#aabed0;font-weight:400;font-size:14px;margin-bottom:6px}
.detail-grid span,.detail-fact span {font-size:16px;color:#e4edf4}
.notes-grid {display:grid;grid-template-columns:repeat(auto-fit,minmax(260px,1fr));gap:12px;margin-top:17px}
.detail-note strong {color:#ddbd8b;font-size:15px;font-weight:400}
.detail-note p {white-space:pre-wrap;overflow-wrap:anywhere;margin:7px 0 0;font-size:15px}
.key {display:block;padding:14px 17px;margin:14px 0;border:1px solid rgba(216,186,138,.34);
  border-radius:9px;background:rgba(5,16,26,.6);color:#dceace;
  font:400 15px/1.5 Consolas,monospace;overflow-wrap:anywhere}
.row-sub {display:block;margin-top:5px;font-size:13px}
/* User-edited computer names stay readable even when the detected name is long. */
.owner-machine-display {display:block;max-width:460px;white-space:normal;overflow-wrap:anywhere;line-height:1.45}
/* OWNER pending queue: name wraps to two lines, all main actions fit side-by-side. */
.pending-computers-table {min-width:1220px;table-layout:fixed}
.pending-computers-table th,.pending-computers-table td {padding:13px 10px}
.pending-computers-table td:first-child strong {white-space:nowrap}
.pending-computers-table td:nth-child(5) {font-size:14px;white-space:nowrap}
.pending-name-column {min-width:0}
.pending-name-head {display:grid;grid-template-columns:minmax(0,1fr) 33px;
  align-items:center;gap:8px;min-width:0}
.pending-name-text {display:-webkit-box;-webkit-box-orient:vertical;-webkit-line-clamp:2;
  max-width:none;max-height:2.9em;line-height:1.4;overflow:hidden;
  white-space:normal;overflow-wrap:anywhere}
.pending-edit-name {width:33px;min-height:33px;padding:0;flex:none;
  border:1px solid rgba(136,184,213,.43);border-radius:8px;
  background:rgba(33,69,96,.5);color:#bee2fc;font-size:18px}
.pending-edit-name:hover {border-color:#81c6f3}
.pending-primary-actions {min-width:375px}
.pending-actions-row {display:flex;align-items:center;justify-content:flex-start;
  gap:9px;white-space:nowrap}
.pending-actions-row>.button-link.compact,.pending-archive-trigger {min-height:40px;
  padding:9px 11px;font-size:13px;line-height:1.2;letter-spacing:0;white-space:nowrap}
.pending-archive-trigger {border-color:rgba(237,64,86,.55);
  background:linear-gradient(115deg,rgba(124,37,53,.58),rgba(82,29,42,.53))}
.pending-edit-name:focus-visible,.pending-archive-trigger:focus-visible {
  outline:2px solid var(--focus);outline-offset:3px}
.pending-owner-dialog {box-sizing:border-box;width:min(500px,calc(100vw - 30px));
  max-width:calc(100vw - 30px);max-height:85vh;overflow:auto;
  padding:26px 28px;background:#102337;color:#e5edf5;
  border:1px solid rgba(148,181,204,.52);border-radius:15px;
  box-shadow:0 25px 70px rgba(0,0,0,.6)}
.pending-owner-dialog::backdrop {background:rgba(2,8,16,.78);backdrop-filter:blur(3px)}
.pending-owner-dialog h3 {font-size:23px;line-height:1.25;margin:0 0 13px;font-weight:500}
.pending-owner-dialog p {font-size:14px;line-height:1.55;color:#bfcedc;margin:0 0 18px;
  overflow-wrap:anywhere;white-space:normal}
.pending-owner-dialog label {font-size:14px}
.pending-owner-dialog .pending-name-reset-hint {margin:-5px 0 0;font-size:12px}
.pending-dialog-buttons {display:flex;align-items:center;justify-content:flex-end;
  gap:10px;flex-wrap:wrap;margin-top:18px}
.pending-dialog-buttons form {display:block;margin:0}
.pending-dialog-buttons button {min-height:41px;padding:10px 14px;font-size:13px}
.pending-dialog-buttons .pending-cancel-button {
  background:linear-gradient(115deg,#294255,#1b3046);border-color:rgba(171,193,210,.35)}
.pending-dialog-buttons .pending-confirm-archive {background:linear-gradient(115deg,#9c3248,#692539);
  border-color:rgba(237,64,86,.65)}
.settings-hero {border-color:rgba(133,174,199,.3)!important}
footer {font-size:14px;color:#8fa3b5}
@media(max-width:1190px) {
  .workspace-shell {grid-template-columns:222px minmax(0,1fr)}
  .workspace-sidebar {padding:25px 11px}
  main {padding:25px 22px 54px}
}
@media(max-width:850px) {
  .workspace-shell {display:block}
  .workspace-sidebar {position:relative;height:auto;overflow:visible;display:block;padding:15px 16px 12px;
    border-right:0;border-bottom:1px solid var(--line)}
  .workspace-sidebar:before {height:2px;width:auto;right:0;top:auto;bottom:0}
  .brand-home {padding:4px 2px 15px}
  .brand-emblem {width:39px;height:39px}
  .nav-group-label,.rail-bottom {display:none}
  nav {display:flex;flex-direction:row;overflow-x:auto;gap:7px;white-space:nowrap;
    padding-bottom:4px;margin:0}
  nav a {padding:8px 12px;min-height:39px;flex:none;font-size:14px}
  .nav-icon {width:16px;font-size:16px}
  .workspace-topbar {padding:17px 20px}
  main {padding:22px 18px 45px}
}
@media(max-width:600px) {
  .workspace-topbar {padding:14px 16px}
  .topbar-title {font-size:16px}
  .topbar-owner {display:none}
  .card,.card.panel-hero {padding:20px 17px;border-radius:13px}
  main {padding:15px 11px 40px}
  h1 {font-size:27px}
  .metrics {grid-template-columns:repeat(2,minmax(0,1fr));gap:9px}
  .metric {padding:15px;min-height:96px}
  .metric strong {font-size:27px}
  .section-head {align-items:flex-start}
  .telemetry-status {align-items:flex-start}
  .filter-bar {display:grid;grid-template-columns:1fr}
  .hub-grid {grid-template-columns:1fr}
  .hub-tile {min-height:140px}
  .grid {grid-template-columns:1fr}
  .detail-grid,.detail-facts,.notes-grid {grid-template-columns:1fr}
  .pagination {justify-content:space-between}
}
@media(prefers-reduced-motion:reduce) {
  * {scroll-behavior:auto!important;transition:none!important}
}
/* Compact OWNER V12 layout — desktop-first but with spacious touch targets. */
.workspace-sidebar {padding:18px 13px 16px}
.brand-home {padding:5px 7px 20px}
.brand-emblem {border-radius:12px;width:48px;height:48px;color:#ebf4fb;border-color:rgba(62,174,232,.46);
  background:radial-gradient(circle at 28% 24%,rgba(63,177,242,.28),transparent 67%),linear-gradient(155deg,#18324c,#0b192b);
  box-shadow:inset 0 1px rgba(255,255,255,.18),0 0 16px rgba(44,145,210,.15)}
.brand-emblem svg {width:37px;height:37px;filter:drop-shadow(0 0 4px rgba(35,175,235,.17))}
.brand-multi {color:#eaf1f9}
.brand-servis {color:#65c9ef}
.brand-caption {letter-spacing:.055em;font-size:11px}
.workspace-topbar {padding:12px clamp(18px,2vw,28px)}
.topbar-kicker {color:#78d2ee;font-size:11px}
.topbar-title {font-size:15px}
main {padding:17px clamp(18px,2.1vw,32px) 36px}
.card {padding:17px clamp(17px,1.65vw,24px);margin-bottom:12px;border-radius:15px}
.card.panel-hero {padding:19px clamp(20px,2vw,28px);
  background:radial-gradient(circle at 92% 14%,rgba(20,167,219,.13),transparent 40%),
    radial-gradient(circle at 70% 60%,rgba(216,170,90,.055),transparent 46%),
    linear-gradient(115deg,#14283c,#0e1e31 75%,#0d1c2e)}
.card.panel-hero::after {content:"";position:absolute;pointer-events:none;
  right:2%;top:-55px;width:215px;height:215px;border:1px solid rgba(96,193,234,.1);
  border-radius:50%;box-shadow:0 0 0 17px rgba(40,124,168,.025),
  0 0 0 51px rgba(41,132,170,.018),inset 0 0 40px rgba(37,157,214,.035)}
.card.panel-hero > * {position:relative;z-index:1}
.card.panel-hero h1 {font-size:clamp(25px,2vw,32px);margin-bottom:5px}
.card.panel-hero p {font-size:15px;line-height:1.42;max-width:960px}
.eyebrow {margin-bottom:5px;letter-spacing:.09em;color:#77d8f3;font-size:12px}
.section-head {gap:10px;margin-bottom:10px}
.section-head p {line-height:1.42}
.metrics {gap:9px;margin-top:12px;grid-template-columns:repeat(auto-fit,minmax(145px,1fr))}
.metric {min-height:80px;padding:13px 15px;border-radius:11px;
  background:linear-gradient(145deg,rgba(24,45,63,.67),rgba(10,24,38,.78))}
.metric b {margin-bottom:4px;font-size:13px;line-height:1.3}
.metric strong {font-size:clamp(24px,2vw,29px)}
.metric small {margin-top:4px}
.dashboard-hero .metrics {grid-template-columns:repeat(3,minmax(0,1fr))}
.dashboard-hero .metric {min-height:75px}
.hub-grid {margin-top:10px;gap:10px;grid-template-columns:repeat(4,minmax(0,1fr))}
.hub-tile {min-height:125px;padding:15px 16px;gap:4px;position:relative;
  background:linear-gradient(145deg,rgba(30,59,82,.6),rgba(11,28,46,.9))}
.hub-tile::before {content:"";position:absolute;right:14px;top:12px;width:35px;height:35px;
  border:1px solid rgba(110,205,244,.15);transform:rotate(24deg);border-radius:10px;
  box-shadow:0 0 18px rgba(36,142,194,.06)}
.hub-symbol {font-size:25px;line-height:1;filter:drop-shadow(0 0 6px rgba(70,166,225,.35))}
.hub-tile strong {font-size:16px}
.hub-tile>span:not(.hub-symbol),.hub-tile small {font-size:12px;line-height:1.35}
.summary-footnote {padding-block:13px}
.summary-footnote .detail-facts {margin-top:8px}
.summary-footnote .detail-fact {padding:9px 13px}
.card:before {left:19px;right:19px}
.filter-tabs {margin:10px 0;gap:7px}
.filter-tab {padding:7px 11px}
.service-search {margin:0 0 10px;gap:9px}
.service-search label {font-size:13px}
.service-search input {min-height:41px}
.service-search button {min-height:41px}
.list-size-control {display:flex;align-items:center;gap:6px;color:var(--subtle);font-size:13px}
.list-size-control .filter-tab {padding:6px 10px}
table th,table td {padding:8px 11px}
.row-sub {margin-top:2px}
.pagination {padding-top:10px}
.detail-grid,.detail-facts,.notes-grid {margin-top:11px;gap:9px}
.detail-grid>div,.detail-fact,.detail-note {padding:11px 13px}
.finance-disclosure {padding:0}
.finance-disclosure>summary,.statistics-table-disclosure>summary {cursor:pointer;display:flex;
  justify-content:space-between;align-items:center;gap:15px;
  min-height:55px;padding:15px 21px;color:#e7eef5;font-size:18px;list-style:none}
.finance-disclosure>summary::-webkit-details-marker,.statistics-table-disclosure>summary::-webkit-details-marker {display:none}
.finance-disclosure[open]>summary {border-bottom:1px solid var(--line)}
.finance-disclosure>.metrics,.finance-disclosure>p {margin:15px 20px}
.finance-disclosure-hint {font-size:13px;color:var(--subtle)}
/* The entire monetary report is closed by default; only handover count stays visible. */
.statistics-finance-disclosure {padding:0}
.statistics-finance-disclosure>summary {cursor:pointer;display:flex;align-items:center;
  justify-content:space-between;gap:14px;min-height:62px;padding:17px 21px;
  font-size:18px;color:var(--text);list-style:none}
.statistics-finance-disclosure>summary::-webkit-details-marker {display:none}
.statistics-finance-disclosure>summary:focus-visible {outline:2px solid var(--focus);outline-offset:-3px}
.statistics-finance-disclosure[open]>summary {border-bottom:1px solid var(--line)}
.statistics-finance-disclosure .statistics-finance-hint {font-size:13px;color:var(--subtle)}
.statistics-finance-content {padding:17px 21px 22px}
.statistics-finance-content>p {margin:0 0 12px;font-size:14px}
.statistics-finance-content .statistics-trend {margin-top:24px;margin-bottom:21px}
.statistics-finance-content .statistics-table-disclosure {border:1px solid var(--line);
  border-radius:10px;background:rgba(4,13,24,.2);margin-bottom:15px}
.statistics-finance-content .statistics-footnote {margin:15px 0 0}
.statistics-hero {display:block}
.statistics-filter-tabs {margin:11px 0 0}
.statistics-period-controls {display:flex;gap:8px;flex-wrap:wrap;align-items:end;margin:10px 0 0}
.statistics-period-controls form,.statistics-period-controls label {display:flex;gap:8px;align-items:center}
.statistics-period-controls form {margin:0}
.statistics-period-controls input,.statistics-period-controls select {width:auto;min-width:100px;min-height:37px;padding:7px 9px;font-size:14px}
.statistics-period-controls button,.statistics-period-controls .button-link {min-height:37px;padding:7px 12px}
.statistics-metrics {grid-template-columns:repeat(3,minmax(0,1fr))}
.statistics-metrics .metric {min-height:87px}
.statistics-metrics .metric strong.money {font-size:clamp(20px,2vw,27px)}
.statistics-trend {padding-bottom:15px}
.finance-trend-row {display:grid;grid-template-columns:80px minmax(0,1fr) 135px;
  gap:15px;align-items:center;padding:7px 3px;border-bottom:1px solid rgba(147,180,205,.08)}
.finance-trend-row>span {color:var(--muted);font-size:13px}
.finance-trend-row b {font-size:14px;text-align:right;font-weight:400;font-variant-numeric:tabular-nums}
.finance-trend-bars {display:grid;gap:4px;min-width:0}
.finance-trend-bars i {display:block;min-width:2px;height:7px;border-radius:99px}
.finance-trend-revenue {background:linear-gradient(90deg,#247bad,#85d3ec)}
.finance-trend-cost {background:linear-gradient(90deg,#98384e,#ee8a95)}
.statistics-table-disclosure {padding:0}
.statistics-table-disclosure .table-wrap {margin:4px 19px 19px}
.statistics-footnote {font-size:13px;color:var(--subtle);padding-inline:3px}
@media(max-width:1190px) {
  .hub-grid {grid-template-columns:repeat(2,minmax(0,1fr))}
  .workspace-shell {grid-template-columns:215px minmax(0,1fr)}
}
@media(max-width:850px) {
  .workspace-sidebar {padding:12px}
  main {padding:16px 14px 30px}
  .dashboard-hero .metrics,.statistics-metrics {grid-template-columns:repeat(2,minmax(0,1fr))}
}
@media(max-width:600px) {
  .hub-grid {grid-template-columns:1fr}
  .hub-tile {min-height:95px}
  .metrics {grid-template-columns:repeat(2,minmax(0,1fr))}
  .list-size-control {margin-top:4px}
  .finance-trend-row {grid-template-columns:55px minmax(0,1fr) 92px;gap:8px}
  .finance-trend-row b {font-size:12px}
  .finance-disclosure>summary {align-items:start;flex-direction:column;gap:3px}
  .statistics-finance-disclosure>summary {align-items:start;flex-direction:column;gap:3px}
  .statistics-finance-content {padding:15px}
}

"""
