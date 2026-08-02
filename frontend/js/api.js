// PRAETOR Shared API Client Layer
const BASE_URL = window.location.protocol.startsWith('http') ? window.location.origin : 'http://localhost:8000';

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

// Utility: Helper function to determine color based on risk score
function riskColor(score) {
  if (score >= 80) return 'var(--red)';
  if (score >= 60) return 'var(--orange)';
  if (score >= 40) return 'var(--yellow)';
  return 'var(--green)';
}

function riskBadgeClass(score) {
  if (score >= 80) return 'badge-critical';
  if (score >= 60) return 'badge-high';
  if (score >= 40) return 'badge-medium';
  return 'badge-low';
}
