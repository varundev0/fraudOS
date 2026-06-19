import { useState } from 'react';
import { useNavigate } from 'react-router-dom';
import { api } from '../api/client';

export default function Login() {
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [error, setError] = useState('');
  const [loading, setLoading] = useState(false);
  const nav = useNavigate();

  const connect = async () => {
    if (!email.trim() || !password) return;
    setLoading(true);
    setError('');
    try {
      await api.login(email.trim(), password);
      nav('/');
    } catch (e) {
      setError(e.message === 'Invalid credentials' ? 'Invalid email or password' : 'Connection failed');
    } finally {
      setLoading(false);
    }
  };

  const inputStyle = {
    background: 'var(--surface)',
    border: '1px solid var(--border)',
    color: 'var(--text)',
    padding: '13px 16px',
    fontSize: '0.95rem',
    outline: 'none',
    width: '100%',
  };

  return (
    <div style={{ minHeight: '100vh', display: 'flex', flexDirection: 'column', alignItems: 'center', justifyContent: 'center', gap: 28 }}>
      <div style={{ textAlign: 'center' }}>
        <div style={{ fontFamily: 'monospace', fontSize: 'clamp(2.5rem,8vw,4rem)', fontWeight: 900, letterSpacing: '0.25em', color: 'var(--cyan)' }}>FRAUDOS</div>
        <div style={{ fontSize: '0.72rem', color: 'var(--muted)', letterSpacing: '0.2em', textTransform: 'uppercase', marginTop: 6 }}>AI-Native Fraud Investigation Platform</div>
      </div>

      <div style={{ display: 'flex', flexDirection: 'column', gap: 10, width: 'min(340px, 90vw)' }}>
        <input
          value={email}
          onChange={e => setEmail(e.target.value)}
          onKeyDown={e => e.key === 'Enter' && connect()}
          placeholder="Email"
          type="email"
          autoComplete="email"
          disabled={loading}
          style={inputStyle}
          onFocus={e => e.target.style.borderColor = 'var(--cyan)'}
          onBlur={e => e.target.style.borderColor = 'var(--border)'}
        />
        <input
          value={password}
          onChange={e => setPassword(e.target.value)}
          onKeyDown={e => e.key === 'Enter' && connect()}
          placeholder="Password"
          type="password"
          autoComplete="current-password"
          disabled={loading}
          style={inputStyle}
          onFocus={e => e.target.style.borderColor = 'var(--cyan)'}
          onBlur={e => e.target.style.borderColor = 'var(--border)'}
        />
        {error && (
          <div style={{ color: 'var(--risk-block)', fontSize: '0.82rem', padding: '4px 0' }}>{error}</div>
        )}
        <button
          onClick={connect}
          disabled={loading || !email.trim() || !password}
          style={{
            background: loading ? 'var(--surface2)' : 'var(--cyan)',
            border: 'none',
            color: loading ? 'var(--muted)' : '#000',
            padding: '13px',
            fontWeight: 700,
            letterSpacing: '0.12em',
            fontSize: '0.88rem',
            cursor: loading ? 'default' : 'pointer',
          }}
        >
          {loading ? 'CONNECTING...' : 'SIGN IN'}
        </button>
      </div>

      <div style={{ fontSize: '0.68rem', color: 'var(--muted)', letterSpacing: '0.05em' }}>
        All data encrypted in transit · PII tokenized before AI processing
      </div>
    </div>
  );
}
