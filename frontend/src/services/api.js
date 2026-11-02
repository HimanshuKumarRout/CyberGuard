/**
 * CYBERGUARD API Client Service
 */

export const api = {
  // Telemetry & Stats
  async getDashboardStats() {
    const res = await fetch('/api/dashboard/stats');
    if (!res.ok) throw new Error('Failed to fetch stats');
    return res.json();
  },

  async getDashboardTimeline() {
    const res = await fetch('/api/dashboard/timeline');
    if (!res.ok) throw new Error('Failed to fetch timeline');
    return res.json();
  },

  async getDashboardCategories() {
    const res = await fetch('/api/dashboard/categories');
    if (!res.ok) throw new Error('Failed to fetch categories');
    return res.json();
  },

  // Events & Incidents
  async getEvents(limit = 50, offset = 0) {
    const res = await fetch(`/api/events?limit=${limit}&offset=${offset}`);
    if (!res.ok) throw new Error('Failed to fetch events');
    return res.json();
  },

  async getEventById(eventId) {
    const res = await fetch(`/api/events/${eventId}`);
    if (!res.ok) throw new Error('Failed to fetch event detail');
    return res.json();
  },

  async getIncidents(status = null) {
    const url = status ? `/api/incidents?status=${encodeURIComponent(status)}` : '/api/incidents';
    const res = await fetch(url);
    if (!res.ok) throw new Error('Failed to fetch incidents');
    return res.json();
  },

  async updateIncident(incidentId, payload) {
    const res = await fetch(`/api/incidents/${incidentId}`, {
      method: 'PATCH',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(payload)
    });
    if (!res.ok) throw new Error('Failed to update incident');
    return res.json();
  },

  // Threat Detection Pipeline
  async analyzePhishing(payload) {
    const res = await fetch('/api/analyze/phishing', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(payload)
    });
    if (!res.ok) throw new Error('Phishing analysis failed');
    return res.json();
  },

  async analyzeImpersonation(payload) {
    const res = await fetch('/api/analyze/impersonation', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(payload)
    });
    if (!res.ok) throw new Error('Impersonation analysis failed');
    return res.json();
  },

  async analyzeAnomaly(payload) {
    const res = await fetch('/api/analyze/anomaly', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(payload)
    });
    if (!res.ok) throw new Error('Anomaly analysis failed');
    return res.json();
  },

  // Containment Execution
  async executeResponse(payload) {
    const res = await fetch('/api/responses/execute', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(payload)
    });
    if (!res.ok) throw new Error('Response action execution failed');
    return res.json();
  },

  // Models Telemetry
  async getModels() {
    const res = await fetch('/api/models');
    if (!res.ok) throw new Error('Failed to fetch models');
    return res.json();
  },

  // SOC Authentication
  async login(email, password) {
    const res = await fetch('/api/auth/login', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ email, password })
    });
    if (!res.ok) {
      const err = await res.json().catch(() => ({}));
      throw new Error(err.detail || 'Login failed');
    }
    return res.json();
  },

  async register(name, email, password, role = 'Tier-1 SOC Lead') {
    const res = await fetch('/api/auth/register', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ name, email, password, role })
    });
    if (!res.ok) {
      const err = await res.json().catch(() => ({}));
      throw new Error(err.detail || 'Registration failed');
    }
    return res.json();
  },

  async getMe(token) {
    const res = await fetch(`/api/auth/me?token=${encodeURIComponent(token)}`);
    if (!res.ok) throw new Error('Failed to retrieve user profile');
    return res.json();
  }
};
