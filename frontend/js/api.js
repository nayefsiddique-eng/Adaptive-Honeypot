// MIRAGE Shared API Client Layer
const BASE_URL = 'http://localhost:8000';

async function handleApiCall(url, fallback) {
  try {
    const response = await fetch(url);
    if (!response.ok) {
      console.warn(`API query returned status: ${response.status} on ${url}`);
      return fallback;
    }
    return await response.json();
  } catch (error) {
    console.warn(`Connection failed on ${url}: ${error.message}`);
    return fallback;
  }
}

async function fetchDashboard() {
  return await handleApiCall(`${BASE_URL}/api/dashboard`, { avg_deception_score: 0.0 });
}

async function fetchSessions() {
  return await handleApiCall(`${BASE_URL}/api/sessions?limit=50`, []);
}

async function fetchLogs(ip = null) {
  const url = ip ? `${BASE_URL}/api/logs?ip=${encodeURIComponent(ip)}` : `${BASE_URL}/api/logs`;
  return await handleApiCall(url, []);
}

async function fetchResearchMetrics() {
  return await handleApiCall(`${BASE_URL}/api/research/metrics`, { new_metrics: {} });
}

async function fetchBehaviorTimeline(sessionId) {
  return await handleApiCall(`${BASE_URL}/api/sessions/${sessionId}/behavior_timeline`, []);
}
