// MIRAGE Shared API Client Layer
const BASE_URL = 'http://localhost:8000';

const fetchers = {
  dashboard: () => fetch(`${BASE_URL}/api/dashboard`)
    .then(r => r.ok ? r.json() : { avg_deception_score: 0.0 })
    .catch(() => ({ avg_deception_score: 0.0 })),
    
  sessions: () => fetch(`${BASE_URL}/api/sessions`)
    .then(r => r.ok ? r.json() : [])
    .catch(() => []),
    
  logs: (ip = '') => {
    const url = ip ? `${BASE_URL}/api/logs?ip=${encodeURIComponent(ip)}` : `${BASE_URL}/api/logs`;
    return fetch(url)
      .then(r => r.ok ? r.json() : [])
      .catch(() => []);
  },
  
  research: () => fetch(`${BASE_URL}/api/research/metrics`)
    .then(r => r.ok ? r.json() : { new_metrics: {} })
    .catch(() => ({ new_metrics: {} })),

  learningCurve: () => fetch(`${BASE_URL}/api/research/learning-curve`)
    .then(r => r.ok ? r.json() : [])
    .catch(() => []),
    
  timeline: (id) => fetch(`${BASE_URL}/api/sessions/${id}/behavior_timeline`)
    .then(r => r.ok ? r.json() : [])
    .catch(() => [])
};

async function checkBackendStatus() {
  try {
    const response = await fetch(`${BASE_URL}/api/dashboard`, { method: 'GET', timeout: 2000 });
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
