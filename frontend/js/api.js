const BASE_URL = 'http://127.0.0.1:8000';

let managementKey = sessionStorage.getItem('praetor_mgmt_key') || '';

function requestManagementKey() {
    if (managementKey) {
        return managementKey;
    }

    const key = window.prompt('Enter the PRAETOR management API key:');

    if (!key) {
        return '';
    }

    managementKey = key.trim();
    sessionStorage.setItem('praetor_mgmt_key', managementKey);
    return managementKey;
}

async function getJSON(path, fallback) {
    try {
        let key = requestManagementKey();

        if (!key) {
            return fallback;
        }

        let response = await fetch(BASE_URL + path, {
            headers: {
                'X-Management-Key': key
            }
        });

        if (response.status === 401) {
            managementKey = ''; sessionStorage.removeItem('praetor_mgmt_key');
            key = requestManagementKey();

            if (!key) {
                return fallback;
            }

            response = await fetch(BASE_URL + path, {
                headers: {
                    'X-Management-Key': key
                }
            });
        }

        if (!response.ok) {
            return fallback;
        }

        return await response.json();

    } catch (error) {
        console.error('API request failed:', error);
        return fallback;
    }
}

async function postJSON(path, headers = {}) {
    let key = requestManagementKey();

    if (!key) {
        return {
            ok: false,
            status: 0,
            body: null
        };
    }

    const requestHeaders = {
        'X-Management-Key': key,
        ...headers
    };

    try {
        const response = await fetch(BASE_URL + path, {
            method: 'POST',
            headers: requestHeaders
        });

        let body = null;

        try {
            body = await response.json();
        } catch (error) {
            body = null;
        }

        if (response.status === 401) {
            managementKey = '';
        }

        return {
            ok: response.ok,
            status: response.status,
            body: body
        };

    } catch (error) {
        console.error('API request failed:', error);

        return {
            ok: false,
            status: 0,
            body: null
        };
    }
}

const api = {
    dashboard: function () {
        return getJSON('/api/dashboard', null);
    },

    sessions: function (limit = 50) {
        return getJSON('/api/sessions?limit=' + limit, []);
    },

    sessionOne: function (id) {
        return getJSON('/api/sessions/' + encodeURIComponent(id), null);
    },

    explain: function (id) {
        return getJSON('/api/sessions/' + encodeURIComponent(id) + '/explain', null);
    },

    logs: function (ip = '') {
        const path = ip
            ? '/api/logs?ip=' + encodeURIComponent(ip)
            : '/api/logs';

        return getJSON(path, []);
    },

    recentLogs: function (limit = 40) {
        return getJSON('/api/logs/recent?limit=' + limit, []);
    },

    attackSummary: function () {
        return getJSON('/api/attacks/summary', null);
    },

    topIPs: function () {
        return getJSON('/api/attacks/top-ips', []);
    },

    topThreats: function () {
        return getJSON('/api/threat-intel/top-threats', []);
    },

    research: function () {
        return getJSON('/api/research/metrics', null);
    },

    learningCurve: function () {
        return getJSON('/api/research/learning-curve', []);
    },

    benchmark: function () {
        return getJSON('/api/research/benchmark', null);
    },

    resetDemo: function (key) {
        return postJSON('/api/admin/reset-demo', {
            'X-Admin-Key': key
        });
    },

    closeSessions: function (key) {
        return postJSON('/api/admin/close-sessions', {
            'X-Admin-Key': key
        });
    },

    guidedDemo: function (key) {
        return postJSON('/api/admin/guided-demo', {
            'X-Admin-Key': key
        });
    }
};

window.api = api;
