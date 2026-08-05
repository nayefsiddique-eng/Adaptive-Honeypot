// PRAETOR Shared API Client Layer
const BASE_URL = (window.location.protocol.startsWith('http') && window.location.port === '8000') 
  ? window.location.origin 
  : 'http://localhost:8000';

const fetchers = {
  dashboard: () => fetch(`${BASE_URL}/api/dashboard`)
    .then(r => r.ok ? r.json() : {})
    .catch(() => ({})),
    
  sessions: () => fetch(`${BASE_URL}/api/sessions`)
    .then(r => r.ok ? r.json() : [])
    .catch(() => []),
    
  logs: (ip = '') => {
    const url = ip ? `${BASE_URL}/api/logs?ip=${encodeURIComponent(ip)}` : `${BASE_URL}/api/logs`;
    return fetch(url)
      .then(r => r.ok ? r.json() : [])
      .catch(() => []);
  },

  recentLogs: (limit = 30) => fetch(`${BASE_URL}/api/logs/recent?limit=${limit}`)
    .then(r => r.ok ? r.json() : [])
    .catch(() => []),
  
  research: () => fetch(`${BASE_URL}/api/research/metrics`)
    .then(r => r.ok ? r.json() : { new_metrics: {} })
    .catch(() => ({ new_metrics: {} })),

  learningCurve: () => fetch(`${BASE_URL}/api/research/learning-curve`)
    .then(r => r.ok ? r.json() : [])
    .catch(() => []),
    
  timeline: (id) => fetch(`${BASE_URL}/api/sessions/${id}/behavior_timeline`)
    .then(r => r.ok ? r.json() : [])
    .catch(() => []),

  explain: (id) => fetch(`${BASE_URL}/api/sessions/${id}/explain`)
    .then(r => r.ok ? r.json() : {})
    .catch(() => ({})),

  report: (id) => fetch(`${BASE_URL}/api/sessions/${id}/report`)
    .then(r => r.ok ? r.json() : {})
    .catch(() => ({})),

  graph: (id) => fetch(`${BASE_URL}/api/sessions/${id}/graph`)
    .then(r => r.ok ? r.json() : {})
    .catch(() => ({})),

  personas: () => fetch(`${BASE_URL}/api/digital-twin/personas`)
    .then(r => r.ok ? r.json() : {})
    .catch(() => ({})),

  simulateTwin: (persona = 'script_kiddie') => fetch(`${BASE_URL}/api/digital-twin/simulate`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ persona })
  }).then(r => r.ok ? r.json() : {}).catch(() => ({})),

  startDemo: () => fetch(`${BASE_URL}/api/demo/start`, { method: 'POST' })
    .then(r => r.ok ? r.json() : {})
    .catch(() => ({})),

  resetDemo: () => fetch(`${BASE_URL}/api/demo/reset`, { method: 'POST' })
    .then(r => r.ok ? r.json() : {})
    .catch(() => ({}))
};

async function checkBackendStatus() {
  try {
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), 3000);
    const response = await fetch(`${BASE_URL}/api/dashboard`, { method: 'GET', signal: controller.signal });
    clearTimeout(timer);
    return response.ok;
  } catch (e) {
    return false;
  }
}

// Risk score → CSS variable color
function riskColor(score) {
  if (score >= 80) return 'var(--severity-critical)';
  if (score >= 60) return 'var(--severity-high)';
  if (score >= 40) return 'var(--severity-medium)';
  return 'var(--severity-low)';
}

// Risk score → badge CSS class
function riskBadgeClass(score) {
  if (score >= 80) return 'badge-critical';
  if (score >= 60) return 'badge-high';
  if (score >= 40) return 'badge-medium';
  return 'badge-low';
}

// ============================================================
// Toast notification system
// ============================================================
function _ensureToastContainer() {
  let c = document.getElementById('toastContainer');
  if (!c) {
    c = document.createElement('div');
    c.id = 'toastContainer';
    c.className = 'toast-container';
    document.body.appendChild(c);
  }
  return c;
}

function showToast(message, severity = 'info') {
  const container = _ensureToastContainer();
  const toast = document.createElement('div');
  toast.className = `toast toast-${severity}`;
  toast.textContent = message;
  container.appendChild(toast);
  setTimeout(() => {
    toast.style.opacity = '0';
    toast.style.transform = 'translateY(12px)';
    toast.style.transition = 'all 0.2s ease';
    setTimeout(() => toast.remove(), 200);
  }, 3500);
}

// ============================================================
// Command palette
// ============================================================
const CMD_PAGES = [
  { label: 'Overview', href: 'index.html', keys: '⌘ 1' },
  { label: 'Operations', href: 'dashboard.html', keys: '⌘ 2' },
  { label: 'Sessions', href: 'sessions.html', keys: '⌘ 3' },
  { label: 'Intelligence', href: 'intel.html', keys: '⌘ 4' },
];

function openCmdPalette() {
  if (document.getElementById('cmdOverlay')) return;
  const overlay = document.createElement('div');
  overlay.id = 'cmdOverlay';
  overlay.className = 'cmd-overlay';
  overlay.innerHTML = `
    <div class="cmd-palette">
      <input class="cmd-input" id="cmdInput" placeholder="Search pages…" autofocus />
      <div class="cmd-results" id="cmdResults"></div>
    </div>
  `;
  document.body.appendChild(overlay);
  overlay.addEventListener('click', (e) => { if (e.target === overlay) closeCmdPalette(); });
  const input = document.getElementById('cmdInput');
  input.addEventListener('input', () => renderCmdResults(input.value));
  input.addEventListener('keydown', (e) => {
    if (e.key === 'Escape') closeCmdPalette();
    if (e.key === 'Enter') {
      const active = document.querySelector('.cmd-item.active');
      if (active) window.location.href = active.dataset.href;
    }
    if (e.key === 'ArrowDown' || e.key === 'ArrowUp') {
      e.preventDefault();
      const items = Array.from(document.querySelectorAll('.cmd-item'));
      const idx = items.findIndex(i => i.classList.contains('active'));
      items.forEach(i => i.classList.remove('active'));
      const next = e.key === 'ArrowDown' ? Math.min(idx + 1, items.length - 1) : Math.max(idx - 1, 0);
      if (items[next]) items[next].classList.add('active');
    }
  });
  renderCmdResults('');
}

function closeCmdPalette() {
  const el = document.getElementById('cmdOverlay');
  if (el) el.remove();
}

function renderCmdResults(query) {
  const container = document.getElementById('cmdResults');
  const q = query.toLowerCase();
  const filtered = CMD_PAGES.filter(p => p.label.toLowerCase().includes(q));
  container.innerHTML = filtered.map((p, i) =>
    `<div class="cmd-item${i === 0 ? ' active' : ''}" data-href="${p.href}" onclick="window.location.href='${p.href}'">
      <span>${p.label}</span>
      <span class="cmd-item-kbd">${p.keys}</span>
    </div>`
  ).join('');
}

document.addEventListener('keydown', (e) => {
  if ((e.ctrlKey || e.metaKey) && e.key === 'k') {
    e.preventDefault();
    openCmdPalette();
  }
  // Number shortcuts
  if ((e.ctrlKey || e.metaKey) && ['1','2','3','4'].includes(e.key)) {
    e.preventDefault();
    const page = CMD_PAGES[parseInt(e.key) - 1];
    if (page) window.location.href = page.href;
  }
});

// ============================================================
// Shared sidebar HTML generator (ensures consistency across pages)
// ============================================================
function renderSidebar(activePage) {
  const pages = [
    { id: 'overview', label: 'Overview', href: 'index.html', icon: '⊞' },
    { id: 'operations', label: 'Operations', href: 'dashboard.html', icon: '◎' },
    { id: 'sessions', label: 'Sessions', href: 'sessions.html', icon: '⊡' },
    { id: 'intelligence', label: 'Intelligence', href: 'intel.html', icon: '◇' },
  ];
  const html = `
    <aside class="sidebar">
      <div class="sidebar-header">
        <a href="index.html" class="brand-logo">
          <div class="brand-icon">P</div>
          <span>PRAETOR</span>
        </a>
      </div>
      <div class="nav-group">
        <div class="nav-label">Navigation</div>
        ${pages.map(p => `
          <a href="${p.href}" class="nav-item${p.id === activePage ? ' active' : ''}">
            <span class="nav-icon">${p.icon}</span> ${p.label}
          </a>
        `).join('')}
        <div class="nav-label" style="margin-top:12px;">Quick actions</div>
        <div class="nav-item" onclick="openCmdPalette()" style="cursor:pointer;">
          <span class="nav-icon">⌘</span> Command palette
          <span class="nav-kbd">Ctrl K</span>
        </div>
      </div>
    </aside>
  `;
  const mount = document.getElementById('sidebarMount');
  if (mount) {
    mount.outerHTML = html;
  }
}
