import { useState, useEffect } from 'react';
import { BrowserRouter, Routes, Route, Navigate } from 'react-router-dom';
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import Login from './pages/Login';
import CaseQueue from './pages/CaseQueue';
import CaseDetail from './pages/CaseDetail';
import { api } from './api/client';
import './index.css';

const qc = new QueryClient();

function Guard({ children }) {
  const [authState, setAuthState] = useState('loading'); // 'loading' | 'authed' | 'unauthed'

  useEffect(() => {
    api.checkAuth()
      .then(r => setAuthState(r.ok ? 'authed' : 'unauthed'))
      .catch(() => setAuthState('unauthed'));
  }, []);

  if (authState === 'loading') {
    return (
      <div style={{ minHeight: '100vh', display: 'flex', alignItems: 'center', justifyContent: 'center' }}>
        <div style={{ fontFamily: 'monospace', fontSize: '0.8rem', color: 'var(--muted)', letterSpacing: '0.15em' }}>
          AUTHENTICATING...
        </div>
      </div>
    );
  }

  if (authState === 'unauthed') return <Navigate to="/login" replace />;
  return children;
}

export default function App() {
  return (
    <QueryClientProvider client={qc}>
      <BrowserRouter>
        <Routes>
          <Route path="/login" element={<Login />} />
          <Route path="/" element={<Guard><CaseQueue /></Guard>} />
          <Route path="/case/:caseId" element={<Guard><CaseDetail /></Guard>} />
          <Route path="*" element={<Navigate to="/" replace />} />
        </Routes>
      </BrowserRouter>
    </QueryClientProvider>
  );
}
