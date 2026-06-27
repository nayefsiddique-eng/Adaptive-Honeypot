// MIRAGE Global API Orchestrator & Client Services

const API = "http://localhost:8000";

// Helper for safe API queries
async function safeFetch(url, options = {}) {
  try {
    const res = await fetch(url, options);
    if (!res.ok) throw new Error(`HTTP Error ${res.status}`);
    return await res.json();
  } catch (e) {
    console.error(`Fetch failure on: ${url}`, e);
    showToast(`Network Error: ${e.message}`, "error");
    return { error: true, message: e.message };
  }
}

// Risk Color code resolver
function riskColor(score) {
  if (score >= 80) return "#ef4444"; // red
  if (score >= 60) return "#f97316"; // orange
  if (score >= 40) return "#eab308"; // yellow
  return "#22c55e"; // green
}

// Toast notification engine
function showToast(message, type = "info") {
  let container = document.getElementById("toastContainer");
  if (!container) {
    container = document.createElement("div");
    container.id = "toastContainer";
    container.className = "toast-container";
    document.body.appendChild(container);
  }

  const toast = document.createElement("div");
  toast.className = `toast ${type === 'error' ? 'toast-error' : type === 'success' ? 'toast-success' : ''}`;
  
  toast.innerHTML = `
    <span class="toast-message">${message}</span>
    <button class="toast-close" onclick="this.parentElement.remove()">×</button>
  `;

  container.appendChild(toast);

  // Auto-remove after 4 seconds
  setTimeout(() => {
    toast.style.opacity = '0';
    toast.style.transform = 'translateY(10px)';
    toast.style.transition = 'all 0.3s ease';
    setTimeout(() => toast.remove(), 300);
  }, 4000);
}

// Shared Navigation Header Initialization
function initHeader() {
  // Highlight active menu item
  const currentPath = window.location.pathname;
  const pageName = currentPath.split("/").pop() || "index.html";
  
  document.querySelectorAll(".nav-item").forEach(item => {
    const link = item.querySelector("a");
    if (link) {
      const href = link.getAttribute("href");
      if (href === pageName) {
        item.classList.add("active");
      } else {
        item.classList.remove("active");
      }
    }
  });

  // Start background stats sync
  syncHeaderStats();
  setInterval(syncHeaderStats, 10000); // sync every 10 seconds
}

// Background poller to refresh navigation metrics
async function syncHeaderStats() {
  const metrics = await safeFetch(`${API}/api/research/metrics`);
  if (metrics.error) return;

  const totalEl = document.getElementById("headerTotalAttacks");
  const activeDecoysEl = document.getElementById("headerActiveDecoys");
  const threatLevelEl = document.getElementById("headerThreatLevel");
  const threatIndicatorEl = document.getElementById("headerThreatIndicator");

  if (totalEl) totalEl.textContent = metrics.total_attacks || 0;
  if (activeDecoysEl) activeDecoysEl.textContent = metrics.active_deception_sessions || 0;

  if (threatLevelEl && threatIndicatorEl) {
    const total = metrics.total_attacks || 0;
    const rate = metrics.false_positive_rate_pct || 0;
    
    let level = "MONITORING";
    let color = "#00ff88"; // green
    
    if (metrics.active_deception_sessions > 0) {
      level = "DECEPTION ENGAGED";
      color = "#a855f7"; // purple
    } else if (total > 50) {
      level = "HIGH THREAT";
      color = "#ef4444"; // red
    } else if (total > 15) {
      level = "EVALUATING INTENT";
      color = "#f97316"; // orange
    }

    threatLevelEl.textContent = level;
    threatLevelEl.style.color = color;
    threatIndicatorEl.style.backgroundColor = color;
    threatIndicatorEl.style.boxShadow = `0 0 8px ${color}`;
  }
}

// Load common header stats immediately
document.addEventListener("DOMContentLoaded", initHeader);
