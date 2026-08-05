const BASE_URL = window.location.protocol.startsWith('http')
  ? window.location.origin
  : 'http://localhost:8000';

async function getJSON(path, fallback) {
  try {
    const res = await fetch(`${BASE_URL}${path}`);
    if (!res.ok) return fallback;
    return await res.json();
  } catch (e) {
    return fallback;
  }
}

async function postJSON(path, headers = {}) {
  const res = await fetch(`${BASE_URL}${path}`, { method: 'POST', headers });
  let body = null;
  try { body = await res.json(); } catch (e) { /* no body */ }
  return { ok: res.ok, status: res.status, body };
}

const api = {
  dashboard:     () => getJSON('/api/dashboard', null),
  sessions:      (limit = 50) => getJSON(`/api/sessions?limit=${limit}`, []),
  sessionOne:    (id) => getJSON(`/api/sessions/${encodeURIComponent(id)}`, null),
  explain:       (id) => getJSON(`/api/sessions/${encodeURIComponent(id)}/explain`, null),
  logs:          (ip = '') => getJSON(ip ? `/api/logs?ip=${encodeURIComponent(ip)}` : '/api/logs', []),
  recentLogs:    (limit = 40) => getJSON(`/api/logs/recent?limit=${limit}`, []),
  attackSummary: () => getJSON('/api/attacks/summary', null),
  topIPs:        () => getJSON('/api/attacks/top-ips', []),
  topThreats:    () => getJSON('/api/threat-intel/top-threats', []),
  research:      () => getJSON('/api/research/metrics', null),
  learningCurve: () => getJSON('/api/research/learning-curve', []),
  benchmark:     () => getJSON('/api/research/benchmark', null),

  resetDemo:     (key) => postJSON('/api/admin/reset-demo', { 'X-Admin-Key': key }),
  closeSessions: (key) => postJSON('/api/admin/close-sessions', { 'X-Admin-Key': key }),
  guidedDemo:    (key) => postJSON('/api/admin/guided-demo', { 'X-Admin-Key': key }),
};
