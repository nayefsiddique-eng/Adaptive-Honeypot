const BASE_URL = 'http://127.0.0.1:8000';

function getManagementKey() {
  return sessionStorage.getItem('praetor_management_key') || '';
}

function requestManagementKey() {
  const existing = getManagementKey();

  const key = window.prompt(
    existing
      ? 'Management API authentication failed. Enter the management API key again:'
      : 'Enter the PRAETOR management API key:'
  );

  if (!key) {
    return '';
  }

  sessionStorage.setItem('praetor_management_key', key);
  return key;
}

async function getJSON(path, fallback) {
  try {
    let key = getManagementKey();

    let res = await fetch(`${BASE_URL}${path}`, {
      headers: key ? { 'X-Management-Key': key } : {}
    });

    if (res.status === 401) {
      key = requestManagementKey();

      if (!key) {
        return fallback;
      }

      res = await fetch(`${BASE_URL}${path}`, {
        headers: { 'X-Management-Key': key }
      });

      if (res.status === 401) {
        sessionStorage.removeItem('praetor_management_key');
        return fallback;
      }
    }

    if (!res.ok) return fallback;

    return await res.json();
  } catch (e) {
    return fallback;
  }
}

async function postJSON(path, headers = {}) {
  const managementKey = getManagementKey();

  const mergedHeaders = {
    ...(managementKey ? { 'X-Management-Key': managementKey } : {}),
    ...headers
  };

  const res = await fetch(`${BASE_URL}${path}`, {
    method: 'POST',
    headers: mergedHeaders
  });

  let body = null;

  try {
    body = await res.json();
  } catch (e) {
    // Response may intentionally contain no JSON body.
  }

  return { ok: res.ok, status: res.status, body };
}

const api = {
  dashboard:     () => getJSON('/api/dashboard', null),
  sessions:      (limit = 50) => getJSON(`/api/sessions?limit=${limit}`, []),
  sessionOne:    (id) => getJSON(`/api/sessions/${encodeURIComponent(id)}`, null),
  explain:       (id) => getJSON(`/api/sessions/${encodeURIComponent(id)}/explain`, null),
  logs:          (ip = '') => getJSON(
    ip ? `/api/logs?ip=${encodeURIComponent(ip)}` : '/api/logs',
    []
  ),
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

