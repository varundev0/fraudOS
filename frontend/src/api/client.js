// All requests use relative URLs so the Vite dev proxy (→ :8000) and the
// production reverse-proxy both work without configuration changes.
const BASE = import.meta.env.VITE_API_URL || '';

export { MOCK_CASES } from './mock-data';

// Only block explicit non-localhost http:// URLs (relative paths are fine).
const isLocalhost = (url) => !url || /^https?:\/\/(localhost|127\.|0\.0\.0\.0)/.test(url);
const assertHttps = (url) => {
  if (url && url.startsWith('http://') && !isLocalhost(url)) {
    throw new Error('Insecure connection: API URL must use HTTPS in non-local environments');
  }
};

const handle401 = () => {
  window.location.replace('/login');
};

const parseResponse = async (r) => {
  if (r.status === 401) { handle401(); throw new Error('Not authenticated'); }
  if (!r.ok) throw new Error(`Request failed (${r.status})`);
  return r.json();
};

const parseTextResponse = async (r) => {
  if (r.status === 401) { handle401(); throw new Error('Not authenticated'); }
  if (!r.ok) throw new Error(`Request failed (${r.status})`);
  return r.text();
};

export const api = {
  login: async (email, password) => {
    assertHttps(BASE);
    const r = await fetch(`${BASE}/auth`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      credentials: 'include',
      body: JSON.stringify({ email, password }),
    });
    if (r.status === 401) throw new Error('Invalid credentials');
    if (!r.ok) throw new Error(`Request failed (${r.status})`);
    return r.json();
  },

  checkAuth: () => {
    assertHttps(BASE);
    return fetch(`${BASE}/auth/me`, { credentials: 'include' });
  },

  getMe: async () => {
    assertHttps(BASE);
    const r = await fetch(`${BASE}/auth/me`, { credentials: 'include' });
    if (!r.ok) return null;
    return r.json();
  },

  getUsers: () => api.get('/users'),

  createUser: (body) => api.post('/users', body),

  updateUser: async (userId, body) => {
    assertHttps(BASE);
    const r = await fetch(`${BASE}/users/${userId}`, {
      method: 'PATCH',
      headers: { 'Content-Type': 'application/json' },
      credentials: 'include',
      body: JSON.stringify(body),
    });
    if (r.status === 401) { handle401(); throw new Error('Not authenticated'); }
    if (!r.ok) throw new Error(`Request failed (${r.status})`);
    return r.json();
  },

  logout: async () => {
    await fetch(`${BASE}/auth/logout`, { method: 'POST', credentials: 'include' });
    window.location.replace('/login');
  },

  post: (path, body) => {
    assertHttps(BASE);
    return fetch(`${BASE}${path}`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      credentials: 'include',
      body: JSON.stringify(body),
    }).then(parseResponse);
  },

  get: (path) => {
    assertHttps(BASE);
    return fetch(`${BASE}${path}`, { credentials: 'include' }).then(parseResponse);
  },

  getText: (path) => {
    assertHttps(BASE);
    return fetch(`${BASE}${path}`, { credentials: 'include' }).then(parseTextResponse);
  },
};
