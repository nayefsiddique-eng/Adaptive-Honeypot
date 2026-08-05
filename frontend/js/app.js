const REFRESH_MS = 5000;
let currentView = 'overview';
let pollTimer = null;
let feedSeen = new Set();
let traceHistory = []; // rolling buffer of {t, total} for the sparkline

const $ = (sel, root = document) => root.querySelector(sel);
const $$ = (sel, root = document) => Array.from(root.querySelectorAll(sel));

function fmtNum(n) {
  if (n === null || n === undefined) return '—';
  return Number(n).toLocaleString();
}
function fmtTime(iso) {
  if (!iso) return '—';
  try {
    const d = new Date(iso);
    return d.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit', second: '2-digit' });
  } catch (e) { return '—'; }
}
function severityOf(score) {
  if (score >= 80) return 'critical';
  if (score >= 60) return 'high';
  if (score >= 40) return 'medium';
  return 'low';
}
function severityColor(sev) {
  return { critical: 'var(--rust)', high: 'var(--amber-bright)', medium: 'var(--brass)', low: 'var(--moss)' }[sev] || 'var(--ink-faint)';
}
function chip(score) {
  const sev = severityOf(score || 0);
  return `<span class="chip ${sev}">${sev}</span>`;
}
function escapeHtml(s) {
  if (s === null || s === undefined) return '';
  return String(s).replace(/[&<>"']/g, c => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
}
function toast(msg, isErr = false) {
  const host = $('#toastHost');
  const el = document.createElement('div');
  el.className = `toast${isErr ? ' err' : ''}`;
  el.textContent = msg;
  host.appendChild(el);
  setTimeout(() => el.remove(), 4200);
}
// Simple deterministic hash so the same IP always lands at the same
// radar angle from one refresh to the next, instead of jittering around.
function hashAngle(str) {
  let h = 0;
  for (let i = 0; i < str.length; i++) { h = (h * 31 + str.charCodeAt(i)) >>> 0; }
  return (h % 360) * (Math.PI / 180);
}

function switchView(name) {
  currentView = name;
  $$('.nav-btn').forEach(b => b.classList.toggle('active', b.dataset.view === name));
  $$('.view').forEach(v => v.classList.toggle('active', v.id === `view-${name}`));
  loadView(name);
}

// NOTE: 'admin' is intentionally excluded from here — it is only loaded
// once, on switchView. It must never be re-run by the poll timer, or the
// key input gets overwritten mid-keystroke every refresh cycle.
function loadView(name) {
  const loaders = {
    overview: loadOverview,
    feed: loadFeed,
    sessions: loadSessions,
    intel: loadIntel,
    admin: loadAdmin,
  };
  (loaders[name] || (() => {}))();
}

async function checkPulse() {
  const data = await api.dashboard();
  const led = $('#gaugeLed');
  const label = $('#gaugeLabel');
  const needle = $('#gaugeNeedle');
  if (data) {
    led.classList.add('live'); led.classList.remove('down');
    label.textContent = 'trap active';
    const risk = Math.max(0, Math.min(100, data.avg_risk_score || 0));
    // needle sweeps from -90deg (0 risk) to +90deg (100 risk)
    const deg = -90 + (risk / 100) * 180;
    needle.style.transform = `rotate(${deg}deg)`;
    recordTrace(data.total_attacks);
  } else {
    led.classList.remove('live'); led.classList.add('down');
    label.textContent = 'unreachable';
  }
  return data;
}

function recordTrace(total) {
  if (total === null || total === undefined) return;
  const now = Date.now();
  traceHistory.push({ t: now, total: Number(total) });
  const cutoff = now - 10 * 60 * 1000; // keep last 10 minutes
  traceHistory = traceHistory.filter(p => p.t >= cutoff);
  drawTrace();
}

function drawTrace() {
  const canvas = $('#traceCanvas');
  if (!canvas) return;
  const dpr = window.devicePixelRatio || 1;
  const rect = canvas.getBoundingClientRect();
  const w = Math.max(rect.width, 1), h = 64;
  canvas.width = w * dpr; canvas.height = h * dpr;
  canvas.style.height = h + 'px';
  const ctx = canvas.getContext('2d');
  ctx.setTransform(dpr, 0, 0, dpr, 0, 0);
  ctx.clearRect(0, 0, w, h);

  if (traceHistory.length < 2) {
    ctx.fillStyle = 'rgba(184,165,131,0.5)';
    ctx.font = '11px "IBM Plex Mono", monospace';
    ctx.fillText('gathering readings…', 8, h / 2 + 4);
    return;
  }
  const totals = traceHistory.map(p => p.total);
  const min = Math.min(...totals), max = Math.max(...totals);
  const span = Math.max(max - min, 1);
  const pad = 8;

  ctx.beginPath();
  traceHistory.forEach((p, i) => {
    const x = pad + (i / (traceHistory.length - 1)) * (w - pad * 2);
    const y = h - pad - ((p.total - min) / span) * (h - pad * 2);
    if (i === 0) ctx.moveTo(x, y); else ctx.lineTo(x, y);
  });
  ctx.strokeStyle = '#e8a13a';
  ctx.lineWidth = 1.6;
  ctx.stroke();

  // fill under the line
  const lastX = pad + (w - pad * 2);
  ctx.lineTo(lastX, h - pad);
  ctx.lineTo(pad, h - pad);
  ctx.closePath();
  ctx.fillStyle = 'rgba(232,161,58,0.08)';
  ctx.fill();

  // latest point marker
  const last = traceHistory[traceHistory.length - 1];
  const lx = w - pad;
  const ly = h - pad - ((last.total - min) / span) * (h - pad * 2);
  ctx.beginPath();
  ctx.arc(lx, ly, 2.6, 0, Math.PI * 2);
  ctx.fillStyle = '#f7c463';
  ctx.fill();
}

async function loadOverview() {
  const data = await checkPulse();
  if (!data) {
    $('#ovStats').innerHTML = offlineNotice();
    return;
  }
  $('#statTotal').textContent = fmtNum(data.total_attacks);
  $('#statIPs').textContent = fmtNum(data.unique_ips);
  $('#statRisk').textContent = data.avg_risk_score != null ? data.avg_risk_score.toFixed(1) : '—';
  $('#statDeception').textContent = data.avg_deception_score != null ? data.avg_deception_score.toFixed(1) : '—';

  const sevTotal = (data.critical_count||0)+(data.high_count||0)+(data.medium_count||0)+(data.low_count||0);
  const sevRow = (label, count, cls) => {
    const pct = sevTotal ? (count/sevTotal*100) : 0;
    return `<div class="sev-row">
      <span class="chip ${cls}">${label}</span>
      <div class="bar-track" style="flex:1"><div class="bar-fill" style="width:${pct}%; background:${severityColor(cls)}"></div></div>
      <span class="mono dim" style="min-width:34px;text-align:right">${fmtNum(count)}</span>
    </div>`;
  };
  $('#sevBreakdown').innerHTML = sevTotal ? [
    sevRow('critical', data.critical_count, 'critical'),
    sevRow('high', data.high_count, 'high'),
    sevRow('medium', data.medium_count, 'medium'),
    sevRow('low', data.low_count, 'low'),
  ].join('') : `<div class="empty">No captures logged yet — send traffic to /api/logs/ingest to populate this.</div>`;

  const types = Object.entries(data.attack_type_breakdown || {}).sort((a,b)=>b[1]-a[1]);
  $('#typeBreakdown').innerHTML = types.length ? types.map(([t,c]) => {
    const max = types[0][1] || 1;
    return `<div class="sev-row">
      <span class="mono dim" style="min-width:150px;text-transform:capitalize">${escapeHtml(t.replace(/_/g,' '))}</span>
      <div class="bar-track" style="flex:1"><div class="bar-fill" style="width:${(c/max*100)}%"></div></div>
      <span class="mono dim" style="min-width:30px;text-align:right">${c}</span>
    </div>`;
  }).join('') : `<div class="empty">No technique data yet.</div>`;

  const top5 = data.top_5_ips_by_risk || [];
  $('#topIpsList').innerHTML = top5.length ? top5.map(r => `
    <div class="sev-row">
      <span class="mono">${escapeHtml(r.ip_address)}</span>
      <div class="bar-track" style="flex:1"><div class="bar-fill" style="width:${r.risk_score}%; background:${severityColor(severityOf(r.risk_score))}"></div></div>
      <span class="mono dim" style="min-width:40px;text-align:right">${r.risk_score.toFixed(0)}</span>
    </div>`).join('') : `<div class="empty">No attacker origins recorded yet.</div>`;
}

function offlineNotice() {
  return `<div class="notice warn" style="grid-column:1/-1">
    <span>⚠</span>
    <span><b>Backend unreachable.</b> Start it with <code class="mono">uvicorn backend.main:app --reload</code>
    from the project root, then this page will populate automatically — no refresh needed.</span>
  </div>`;
}

async function loadFeed() {
  const logs = await api.recentLogs(40);
  const feedEl = $('#feedList');
  if (!logs || !logs.length) {
    feedEl.innerHTML = `<div class="empty">No traffic captured yet. This feed listens on <span class="mono">/api/logs/recent</span> and updates every ${REFRESH_MS/1000}s.</div>`;
    return;
  }
  feedEl.innerHTML = logs.map(l => {
    const isNew = !feedSeen.has(l.id);
    feedSeen.add(l.id);
    const sev = severityOf(l.risk_score || 0);
    return `<div class="feed-row" style="${isNew ? '' : 'animation:none'}">
      <span class="feed-bead" style="background:${severityColor(sev)}"></span>
      <span class="feed-time mono">${fmtTime(l.timestamp)}</span>
      <div class="feed-main">
        <span class="feed-title"><b>${escapeHtml((l.attack_type||'unknown').replace(/_/g,' '))}</b> from ${escapeHtml(l.ip_address)}${l.country ? ` · ${escapeHtml(l.country)}`: ''}</span>
        <span class="feed-sub">${escapeHtml(l.mitre_technique || 'n/a')} · deception: ${l.deception ? escapeHtml(l.deception.honeypot_state) : 'n/a'} · ${l.response_time_ms != null ? l.response_time_ms.toFixed(1)+'ms' : ''}</span>
      </div>
      ${chip(l.risk_score)}
    </div>`;
  }).join('');
}

async function loadSessions() {
  const sessions = await api.sessions(60);
  const tbody = $('#sessionsBody');
  if (!sessions || !sessions.length) {
    tbody.innerHTML = `<tr><td colspan="8"><div class="empty">No attacker sessions recorded yet.</div></td></tr>`;
    return;
  }
  tbody.innerHTML = sessions.map((s, i) => `
    <tr>
      <td class="ip">${escapeHtml(s.ip_address)}</td>
      <td>${s.is_active ? '<span class="chip medium">active</span>' : '<span class="chip low">closed</span>'}</td>
      <td class="mono dim">${(s.attack_types||[]).slice(0,3).map(t=>escapeHtml(t.replace(/_/g,' '))).join(', ') || '—'}</td>
      <td>${fmtNum(s.attack_count)}</td>
      <td>${chip(s.risk_score)}</td>
      <td class="mono dim">${s.honeypot_state ? escapeHtml(s.honeypot_state) : '—'}</td>
      <td class="mono dim">${s.deception_score_avg != null ? s.deception_score_avg.toFixed(1) : '—'}</td>
      <td class="mono dim">${fmtTime(s.last_seen)}</td>
    </tr>`).join('');

  drawRadar(sessions);
}

// Signature visualization: plots active origins on a radar. Angle is a
// stable hash of the IP (so a given attacker always appears at the same
// bearing), distance from center falls as risk rises.
function drawRadar(sessions) {
  const svg = $('#radarSvg');
  if (!svg) return;
  const size = 280, cx = size / 2, cy = size / 2, maxR = 118;
  const rings = [1, 0.75, 0.5, 0.25].map(f => `
    <circle cx="${cx}" cy="${cy}" r="${maxR * f}" fill="none" stroke="var(--line)" stroke-width="1"/>`).join('');
  const spokes = [0, 45, 90, 135].map(deg => {
    const rad = deg * Math.PI / 180;
    const x1 = cx - Math.cos(rad) * maxR, y1 = cy - Math.sin(rad) * maxR;
    const x2 = cx + Math.cos(rad) * maxR, y2 = cy + Math.sin(rad) * maxR;
    return `<line x1="${x1}" y1="${y1}" x2="${x2}" y2="${y2}" stroke="var(--line-soft)" stroke-width="1"/>`;
  }).join('');

  const blips = (sessions || []).slice(0, 40).map(s => {
    const risk = s.risk_score || 0;
    const angle = hashAngle(s.ip_address || '');
    const dist = maxR * (1 - Math.min(risk, 100) / 100) * 0.92 + maxR * 0.06;
    const x = cx + Math.cos(angle) * dist;
    const y = cy + Math.sin(angle) * dist;
    const sev = severityOf(risk);
    const r = sev === 'critical' ? 5.5 : sev === 'high' ? 4.5 : sev === 'medium' ? 3.6 : 2.8;
    return `<circle cx="${x.toFixed(1)}" cy="${y.toFixed(1)}" r="${r}" fill="${severityColor(sev)}" opacity="0.88">
      <title>${escapeHtml(s.ip_address)} · risk ${risk.toFixed(0)}</title>
    </circle>`;
  }).join('');

  svg.innerHTML = `
    ${rings}${spokes}
    <circle cx="${cx}" cy="${cy}" r="2" fill="var(--amber-bright)"/>
    ${blips}
    ${!sessions || !sessions.length ? `<text x="${cx}" y="${cy}" text-anchor="middle" fill="var(--ink-faint)" font-family="IBM Plex Mono, monospace" font-size="11">no active origins</text>` : ''}
  `;
}

async function loadIntel() {
  const [summary, topIps, threats, sessions] = await Promise.all([
    api.attackSummary(), api.topIPs(), api.topThreats(), api.sessions(60)
  ]);

  const mitreEl = $('#mitreList');
  if (summary && summary.mitre_techniques && Object.keys(summary.mitre_techniques).length) {
    const rows = Object.entries(summary.mitre_techniques);
    mitreEl.innerHTML = rows.map(([id, info]) => `
      <div class="sev-row">
        <span class="mono" style="min-width:70px">${escapeHtml(id)}</span>
        <span class="dim" style="flex:1">${escapeHtml(typeof info === 'object' ? (info.name || info.technique || '') : '')}</span>
        <span class="mono dim">${typeof info === 'object' ? fmtNum(info.count) : fmtNum(info)}</span>
      </div>`).join('');
  } else {
    mitreEl.innerHTML = `<div class="empty">No ATT&CK mappings yet.</div>`;
  }

  const ipsEl = $('#intelTopIps');
  if (topIps && topIps.length) {
    ipsEl.innerHTML = topIps.map(r => `
      <div class="sev-row">
        <span class="mono">${escapeHtml(r.ip_address || r.ip)}</span>
        <span class="dim" style="flex:1">${escapeHtml(r.country || '')}</span>
        <span class="mono dim">${fmtNum(r.attack_count || r.count)}</span>
      </div>`).join('');
  } else {
    ipsEl.innerHTML = `<div class="empty">No IP reputation data yet.</div>`;
  }

  const threatsEl = $('#topThreats');
  if (threats && threats.length) {
    threatsEl.innerHTML = threats.map(t => `
      <div class="sev-row">
        <span class="mono">${escapeHtml(t.ip_address || t.ip)}</span>
        <span class="dim" style="flex:1">${escapeHtml(t.threat_actor_profile || t.classification || '')}</span>
        <span class="mono dim">${t.score != null ? Number(t.score).toFixed(0) : (t.reputation_score != null ? Number(t.reputation_score).toFixed(0) : '—')}</span>
      </div>`).join('');
  } else {
    threatsEl.innerHTML = `<div class="empty">No threat-intel fusion results yet.</div>`;
  }

  drawRadar(sessions);
}

// Only called once per switch into the Admin tab — never on a poll tick.
// Also skips overwriting the field entirely if the user is mid-edit.
function loadAdmin() {
  const input = $('#adminKey');
  if (document.activeElement === input) return;
  const savedKey = sessionStorage.getItem('praetor_admin_key') || '';
  input.value = savedKey;
}

async function runAdminAction(fn, label) {
  const key = $('#adminKey').value.trim();
  if (!key) { toast('Enter the X-Admin-Key value first.', true); return; }
  sessionStorage.setItem('praetor_admin_key', key);
  const { ok, status, body } = await fn(key);
  if (ok) {
    toast(`${label}: success${body && body.message ? ' — ' + body.message : ''}`);
    if (currentView !== 'admin') loadView(currentView);
  } else if (status === 401) {
    toast(`${label}: unauthorized — check the admin key.`, true);
  } else {
    toast(`${label}: failed (${status}).`, true);
  }
}

function startPolling() {
  clearInterval(pollTimer);
  pollTimer = setInterval(() => {
    // Admin is deliberately excluded — it has nothing to live-refresh,
    // and re-running its loader on a timer is what caused the key field
    // to get overwritten while someone was typing into it.
    if (currentView === 'admin') return;
    loadView(currentView);
  }, REFRESH_MS);
}

function wireNav() {
  $$('.nav-btn').forEach(btn => btn.addEventListener('click', () => switchView(btn.dataset.view)));
}

function wireAdmin() {
  $('#btnResetDemo').addEventListener('click', () => {
    if (!confirm('This clears all attack logs, sessions, reputation data and the learned policy. Continue?')) return;
    runAdminAction(api.resetDemo, 'Clear all captured data');
  });
  $('#btnCloseSessions').addEventListener('click', () => runAdminAction(api.closeSessions, 'Close active sessions'));
  $('#btnGuidedDemo').addEventListener('click', () => runAdminAction(api.guidedDemo, 'Scripted scenario'));
}

function wireFeedFilter() {
  const input = $('#ipFilter');
  if (!input) return;
  input.addEventListener('keydown', async (e) => {
    if (e.key !== 'Enter') return;
    const ip = input.value.trim();
    if (!ip) { loadSessions(); return; }
    const logs = await api.logs(ip);
    const tbody = $('#sessionsBody');
    if (!logs.length) {
      tbody.innerHTML = `<tr><td colspan="8"><div class="empty">No logs found for ${escapeHtml(ip)}.</div></td></tr>`;
      return;
    }
    tbody.innerHTML = logs.slice(0,60).map(l => `
      <tr>
        <td class="ip">${escapeHtml(l.ip_address)}</td>
        <td class="mono dim">log</td>
        <td class="mono dim">${escapeHtml((l.attack_type||'').replace(/_/g,' '))}</td>
        <td>1</td>
        <td>${chip(l.risk_score)}</td>
        <td class="mono dim">${escapeHtml(l.mitre_technique || '—')}</td>
        <td class="mono dim">—</td>
        <td class="mono dim">${fmtTime(l.timestamp)}</td>
      </tr>`).join('');
  });
}

window.addEventListener('resize', () => { if (currentView === 'overview') drawTrace(); });

document.addEventListener('DOMContentLoaded', () => {
  wireNav();
  wireAdmin();
  wireFeedFilter();
  switchView('overview');
  startPolling();
});
