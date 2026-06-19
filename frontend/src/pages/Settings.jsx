import { useState } from 'react';
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import Sidebar from '../components/Sidebar';
import { api } from '../api/client';

// Fetch notification status from the backend
async function fetchNotificationStatus() {
  return api.get('/api/notifications/status');
}

const card = (extra = {}) => ({
  background: 'var(--surface)',
  border: '1px solid var(--border)',
  padding: '18px 20px',
  marginBottom: 10,
  ...extra,
});

const lbl = {
  fontSize: '0.62rem',
  color: 'var(--muted)',
  letterSpacing: '0.18em',
  textTransform: 'uppercase',
  marginBottom: 12,
  display: 'block',
};

const row = {
  display: 'flex',
  justifyContent: 'space-between',
  alignItems: 'center',
  padding: '9px 0',
  borderBottom: '1px solid var(--border)',
  fontSize: '0.83rem',
};

const ROLE_COLORS = {
  ADMIN: 'var(--risk-block)',
  SUPERVISOR: '#f59e0b',
  ANALYST: 'var(--cyan)',
};

const SECURITY_LAYERS = [
  { num: 1, name: 'PII Tokenization', desc: 'HMAC-SHA256 tokens replace PII before Claude sees any data' },
  { num: 2, name: 'Input Validation', desc: 'Allowlist regex + field length limits on all alert fields' },
  { num: 3, name: 'Output Sanitization', desc: 'Forbidden fragment scan + Pydantic schema enforcement on Claude output' },
  { num: 4, name: 'Canary Token', desc: 'Per-request canary detects prompt injection attempts' },
  { num: 5, name: 'Constitutional Check', desc: 'Secondary Haiku call audits primary model output' },
  { num: 6, name: 'API Hardening', desc: 'Rate limiting, audit log, HttpOnly session cookies, X-Request-ID' },
];

// ── Users panel (admin only) ──────────────────────────────────────────────────

function UsersPanel() {
  const qc = useQueryClient();
  const [showCreate, setShowCreate] = useState(false);
  const [form, setForm] = useState({ email: '', password: '', full_name: '', role: 'ANALYST' });
  const [formError, setFormError] = useState('');

  const { data: users = [], isLoading } = useQuery({
    queryKey: ['users'],
    queryFn: () => api.getUsers(),
    staleTime: 30_000,
  });

  const createMutation = useMutation({
    mutationFn: () => api.createUser(form),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ['users'] });
      setShowCreate(false);
      setForm({ email: '', password: '', full_name: '', role: 'ANALYST' });
      setFormError('');
    },
    onError: (e) => setFormError(e.message),
  });

  const toggleActive = (user) =>
    api.updateUser(user.id, { is_active: !user.is_active })
       .then(() => qc.invalidateQueries({ queryKey: ['users'] }));

  const changeRole = (user, role) =>
    api.updateUser(user.id, { role })
       .then(() => qc.invalidateQueries({ queryKey: ['users'] }));

  return (
    <div style={card()}>
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 14 }}>
        <span style={{ ...lbl, marginBottom: 0 }}>User Management</span>
        <button
          onClick={() => { setShowCreate(!showCreate); setFormError(''); }}
          style={{ background: 'var(--cyan)', border: 'none', color: '#000', padding: '6px 14px', fontWeight: 700, fontSize: '0.72rem', letterSpacing: '0.1em', cursor: 'pointer' }}
        >
          {showCreate ? 'CANCEL' : '+ ADD USER'}
        </button>
      </div>

      {/* Create user form */}
      {showCreate && (
        <div style={{ background: 'var(--surface2)', border: '1px solid var(--border)', padding: 16, marginBottom: 14, display: 'flex', flexDirection: 'column', gap: 10 }}>
          <div style={{ fontSize: '0.72rem', color: 'var(--muted)', letterSpacing: '0.1em', marginBottom: 2 }}>NEW USER</div>
          {[
            { key: 'email', placeholder: 'Email', type: 'email' },
            { key: 'full_name', placeholder: 'Full name', type: 'text' },
            { key: 'password', placeholder: 'Password (min 8 chars)', type: 'password' },
          ].map(({ key, placeholder, type }) => (
            <input
              key={key}
              type={type}
              placeholder={placeholder}
              value={form[key]}
              onChange={e => setForm(f => ({ ...f, [key]: e.target.value }))}
              style={{ background: 'var(--surface)', border: '1px solid var(--border)', color: 'var(--text)', padding: '9px 12px', fontSize: '0.83rem', outline: 'none' }}
            />
          ))}
          <select
            value={form.role}
            onChange={e => setForm(f => ({ ...f, role: e.target.value }))}
            style={{ background: 'var(--surface)', border: '1px solid var(--border)', color: 'var(--text)', padding: '9px 12px', fontSize: '0.83rem', outline: 'none' }}
          >
            <option value="ANALYST">Analyst</option>
            <option value="SUPERVISOR">Supervisor</option>
            <option value="ADMIN">Admin</option>
          </select>
          {formError && <div style={{ fontSize: '0.78rem', color: 'var(--risk-block)' }}>{formError}</div>}
          <button
            onClick={() => createMutation.mutate()}
            disabled={createMutation.isPending || !form.email || !form.password}
            style={{ background: 'var(--cyan)', border: 'none', color: '#000', padding: '10px', fontWeight: 700, fontSize: '0.82rem', cursor: 'pointer' }}
          >
            {createMutation.isPending ? 'CREATING...' : 'CREATE USER'}
          </button>
        </div>
      )}

      {/* User list */}
      {isLoading ? (
        <div style={{ fontSize: '0.78rem', color: 'var(--muted)', padding: '12px 0' }}>Loading users...</div>
      ) : (
        users.map((user, i) => (
          <div key={user.id} style={{ display: 'flex', alignItems: 'center', gap: 12, padding: '10px 0', borderBottom: i < users.length - 1 ? '1px solid var(--border)' : 'none' }}>
            {/* Avatar */}
            <div style={{ width: 32, height: 32, background: 'var(--surface2)', border: '1px solid var(--border)', display: 'flex', alignItems: 'center', justifyContent: 'center', fontSize: '0.75rem', fontWeight: 700, color: 'var(--cyan)', flexShrink: 0 }}>
              {(user.full_name || user.email)[0].toUpperCase()}
            </div>
            {/* Info */}
            <div style={{ flex: 1, minWidth: 0 }}>
              <div style={{ fontSize: '0.83rem', fontWeight: 600, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
                {user.full_name || '—'}
              </div>
              <div style={{ fontSize: '0.72rem', color: 'var(--muted)', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
                {user.email}
              </div>
            </div>
            {/* Role dropdown */}
            <select
              value={user.role}
              onChange={e => changeRole(user, e.target.value)}
              style={{ background: 'var(--surface2)', border: '1px solid var(--border)', color: ROLE_COLORS[user.role] || 'var(--text)', padding: '4px 8px', fontSize: '0.72rem', fontWeight: 700, letterSpacing: '0.08em', outline: 'none' }}
            >
              <option value="ANALYST">ANALYST</option>
              <option value="SUPERVISOR">SUPERVISOR</option>
              <option value="ADMIN">ADMIN</option>
            </select>
            {/* Active toggle */}
            <button
              onClick={() => toggleActive(user)}
              style={{ background: 'transparent', border: `1px solid ${user.is_active ? 'var(--risk-clear)' : 'var(--muted)'}`, color: user.is_active ? 'var(--risk-clear)' : 'var(--muted)', padding: '4px 10px', fontSize: '0.65rem', fontWeight: 700, letterSpacing: '0.1em', cursor: 'pointer' }}
            >
              {user.is_active ? 'ACTIVE' : 'DISABLED'}
            </button>
          </div>
        ))
      )}
    </div>
  );
}


// ── Main settings page ────────────────────────────────────────────────────────

export default function Settings() {
  const { data: health, isLoading: healthLoading, isError: healthError } = useQuery({
    queryKey: ['health'],
    queryFn: () => api.get('/api/health'),
    retry: 1,
    staleTime: 60_000,
  });

  const { data: me } = useQuery({
    queryKey: ['me'],
    queryFn: () => api.getMe(),
    retry: 1,
    staleTime: 60_000,
  });

  const { data: notifStatus } = useQuery({
    queryKey: ['notificationStatus'],
    queryFn: fetchNotificationStatus,
    retry: 1,
    staleTime: 60_000,
  });

  const isAdmin = me?.role === 'ADMIN';
  const statusColor = healthError ? 'var(--risk-block)' : healthLoading ? 'var(--muted)' : 'var(--risk-clear)';
  const statusLabel = healthError ? 'OFFLINE' : healthLoading ? 'CHECKING...' : 'ONLINE';

  return (
    <div style={{ display: 'flex' }}>
      <Sidebar analyst={{ name: me?.full_name || me?.email || 'Analyst' }} />
      <main style={{ marginLeft: 220, flex: 1, padding: '24px 28px', minHeight: '100vh' }}>

        {/* Header */}
        <div style={{ marginBottom: 24 }}>
          <div style={{ fontWeight: 700, fontSize: '1rem', letterSpacing: '0.08em', textTransform: 'uppercase' }}>Settings</div>
          <div style={{ fontSize: '0.72rem', color: 'var(--muted)', marginTop: 3 }}>System configuration & status</div>
        </div>

        <div style={{ maxWidth: 720 }}>

          {/* System Status */}
          <div style={card()}>
            <span style={lbl}>System Status</span>
            <div style={{ ...row, borderBottom: 'none', paddingTop: 0 }}>
              <span style={{ color: 'var(--muted)', fontSize: '0.82rem' }}>Backend API</span>
              <span style={{ fontSize: '0.78rem', fontWeight: 700, color: statusColor, letterSpacing: '0.1em' }}>
                <span style={{ fontSize: '0.55rem', marginRight: 5 }}>●</span>{statusLabel}
              </span>
            </div>
            {health && (
              <>
                <div style={row}>
                  <span style={{ color: 'var(--muted)' }}>Version</span>
                  <span style={{ fontFamily: 'monospace', fontSize: '0.82rem' }}>{health.version || '—'}</span>
                </div>
                <div style={{ ...row, borderBottom: 'none' }}>
                  <span style={{ color: 'var(--muted)' }}>Primary Model</span>
                  <span style={{ fontFamily: 'monospace', fontSize: '0.82rem', color: 'var(--cyan)' }}>{health.model || '—'}</span>
                </div>
              </>
            )}
          </div>

          {/* Current User / Session */}
          <div style={card()}>
            <span style={lbl}>Your Account</span>
            <div style={row}>
              <span style={{ color: 'var(--muted)' }}>Email</span>
              <span style={{ fontSize: '0.83rem' }}>{me?.email || '—'}</span>
            </div>
            <div style={row}>
              <span style={{ color: 'var(--muted)' }}>Name</span>
              <span style={{ fontSize: '0.83rem' }}>{me?.full_name || '—'}</span>
            </div>
            <div style={row}>
              <span style={{ color: 'var(--muted)' }}>Role</span>
              <span style={{ fontSize: '0.78rem', fontWeight: 700, letterSpacing: '0.1em', color: ROLE_COLORS[me?.role] || 'var(--text)' }}>
                {me?.role || '—'}
              </span>
            </div>
            <div style={{ ...row, borderBottom: 'none' }}>
              <span style={{ color: 'var(--muted)' }}>Session duration</span>
              <span style={{ fontSize: '0.82rem', color: 'var(--muted)' }}>8 hours</span>
            </div>
          </div>

          {/* Admin: User Management */}
          {isAdmin && <UsersPanel />}

          {/* AI Model Configuration */}
          <div style={card()}>
            <span style={lbl}>AI Model Configuration</span>
            <div style={row}>
              <span style={{ color: 'var(--muted)' }}>Investigation model</span>
              <span style={{ fontFamily: 'monospace', fontSize: '0.82rem', color: 'var(--cyan)' }}>
                {health?.model || 'claude-opus-4-6'}
              </span>
            </div>
            <div style={row}>
              <span style={{ color: 'var(--muted)' }}>Constitutional audit model</span>
              <span style={{ fontFamily: 'monospace', fontSize: '0.82rem', color: 'var(--muted)' }}>claude-haiku-4-5-20251001</span>
            </div>
            <div style={row}>
              <span style={{ color: 'var(--muted)' }}>Max tokens (investigation)</span>
              <span style={{ fontFamily: 'monospace', fontSize: '0.82rem' }}>1500</span>
            </div>
            <div style={{ ...row, borderBottom: 'none' }}>
              <span style={{ color: 'var(--muted)' }}>Temperature</span>
              <span style={{ fontFamily: 'monospace', fontSize: '0.82rem' }}>0</span>
            </div>
          </div>

          {/* Notifications */}
          <div style={card()}>
            <span style={lbl}>Notifications</span>
            {/* Slack */}
            <div style={row}>
              <div>
                <div style={{ fontSize: '0.82rem', fontWeight: 600 }}>Slack webhook</div>
                <div style={{ fontSize: '0.7rem', color: 'var(--muted)', marginTop: 2 }}>
                  {notifStatus?.slack?.configured ? 'Webhook URL configured' : (
                    <>Set <code style={{ fontSize: '0.68rem', color: 'var(--cyan)' }}>FRAUDOS_SLACK_WEBHOOK_URL</code> to enable</>
                  )}
                </div>
              </div>
              <span style={{
                fontSize: '0.72rem', fontWeight: 700, letterSpacing: '0.1em',
                color: notifStatus?.slack?.configured ? 'var(--risk-clear)' : 'var(--muted)',
              }}>
                <span style={{ fontSize: '0.5rem', marginRight: 4 }}>●</span>
                {notifStatus ? (notifStatus.slack?.configured ? 'ENABLED' : 'DISABLED') : '—'}
              </span>
            </div>
            {/* Email */}
            <div style={{ ...row, borderBottom: 'none' }}>
              <div>
                <div style={{ fontSize: '0.82rem', fontWeight: 600 }}>Email alerts</div>
                <div style={{ fontSize: '0.7rem', color: 'var(--muted)', marginTop: 2 }}>
                  {notifStatus?.email?.configured ? (
                    <>To: <span style={{ color: 'var(--text)' }}>{notifStatus.email.recipients}</span> via {notifStatus.email.smtp_host}</>
                  ) : (
                    <>Set <code style={{ fontSize: '0.68rem', color: 'var(--cyan)' }}>FRAUDOS_ALERT_EMAIL_TO</code> + <code style={{ fontSize: '0.68rem', color: 'var(--cyan)' }}>FRAUDOS_SMTP_HOST</code> to enable</>
                  )}
                </div>
              </div>
              <span style={{
                fontSize: '0.72rem', fontWeight: 700, letterSpacing: '0.1em',
                color: notifStatus?.email?.configured ? 'var(--risk-clear)' : 'var(--muted)',
              }}>
                <span style={{ fontSize: '0.5rem', marginRight: 4 }}>●</span>
                {notifStatus ? (notifStatus.email?.configured ? 'ENABLED' : 'DISABLED') : '—'}
              </span>
            </div>
            {/* Triggers note */}
            <div style={{ marginTop: 10, padding: '8px 12px', background: 'var(--surface2)', border: '1px solid var(--border)', fontSize: '0.72rem', color: 'var(--muted)' }}>
              Triggers: CRITICAL risk level · BLOCK action · SLA overdue (checked every 10 min)
            </div>
          </div>

          {/* Real-time updates */}
          <div style={card()}>
            <span style={lbl}>Real-time Updates</span>
            <div style={{ ...row, borderBottom: 'none' }}>
              <div>
                <div style={{ fontSize: '0.82rem', fontWeight: 600 }}>WebSocket (/ws)</div>
                <div style={{ fontSize: '0.7rem', color: 'var(--muted)', marginTop: 2 }}>
                  Case Queue auto-refreshes when new investigations complete
                </div>
              </div>
              <span style={{ fontSize: '0.72rem', fontWeight: 700, letterSpacing: '0.1em', color: 'var(--risk-clear)' }}>
                <span style={{ fontSize: '0.5rem', marginRight: 4 }}>●</span>ACTIVE
              </span>
            </div>
            {health && (
              <div style={{ marginTop: 10, padding: '8px 12px', background: 'var(--surface2)', border: '1px solid var(--border)', fontSize: '0.72rem', color: 'var(--muted)' }}>
                Connected clients: {health.ws_clients ?? '—'}
              </div>
            )}
          </div>

          {/* Security Layers */}
          <div style={card()}>
            <span style={lbl}>Security Layers</span>
            {SECURITY_LAYERS.map((layer, i) => (
              <div key={layer.num} style={{ display: 'flex', gap: 14, padding: '10px 0', borderBottom: i < SECURITY_LAYERS.length - 1 ? '1px solid var(--border)' : 'none', alignItems: 'flex-start' }}>
                <div style={{ minWidth: 26, height: 26, background: 'var(--surface2)', border: '1px solid var(--border)', display: 'flex', alignItems: 'center', justifyContent: 'center', fontSize: '0.7rem', fontWeight: 700, color: 'var(--cyan)', flexShrink: 0, marginTop: 1 }}>
                  {layer.num}
                </div>
                <div>
                  <div style={{ fontSize: '0.82rem', fontWeight: 600, marginBottom: 3 }}>{layer.name}</div>
                  <div style={{ fontSize: '0.75rem', color: 'var(--muted)', lineHeight: 1.5 }}>{layer.desc}</div>
                </div>
                <div style={{ marginLeft: 'auto', flexShrink: 0 }}>
                  <span style={{ fontSize: '0.62rem', color: 'var(--risk-clear)', letterSpacing: '0.1em' }}>
                    <span style={{ fontSize: '0.5rem', marginRight: 4 }}>●</span>ACTIVE
                  </span>
                </div>
              </div>
            ))}
          </div>

          {/* Sign out */}
          <div style={card({ padding: '16px 20px' })}>
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
              <div>
                <div style={{ fontSize: '0.82rem', fontWeight: 600 }}>Sign Out</div>
                <div style={{ fontSize: '0.72rem', color: 'var(--muted)', marginTop: 3 }}>Clears session cookie and returns to login</div>
              </div>
              <button
                onClick={() => api.logout()}
                style={{ background: 'transparent', border: '1px solid var(--risk-block)', color: 'var(--risk-block)', padding: '8px 20px', fontWeight: 700, letterSpacing: '0.1em', fontSize: '0.78rem', cursor: 'pointer' }}
                onMouseEnter={e => { e.currentTarget.style.background = '#ef444420'; }}
                onMouseLeave={e => { e.currentTarget.style.background = 'transparent'; }}
              >
                SIGN OUT
              </button>
            </div>
          </div>

          {/* Known Limitations (remaining ones) */}
          <div style={card({ borderColor: '#f59e0b30', background: '#f59e0b08' })}>
            <span style={{ ...lbl, color: '#f59e0b' }}>Known Limitations</span>
            {[
              'PII re-identification map is discarded after each request — no re-identification vault',
              'SAR export produces plain-text draft only — no regulatory e-filing integration',
              'No MFA — password-only authentication',
              'Rate limiting is in-memory and resets on server restart',
            ].map((note, i, arr) => (
              <div key={i} style={{ fontSize: '0.78rem', color: 'var(--muted)', padding: '5px 0', borderBottom: i < arr.length - 1 ? '1px solid var(--border)' : 'none', lineHeight: 1.5 }}>
                <span style={{ color: '#f59e0b', marginRight: 8, fontSize: '0.65rem' }}>⚠</span>{note}
              </div>
            ))}
          </div>

        </div>
      </main>
    </div>
  );
}
