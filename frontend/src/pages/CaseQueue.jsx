import { useState, useMemo, useCallback } from 'react';
import { useQuery } from '@tanstack/react-query';
import Sidebar from '../components/Sidebar';
import CaseCard from '../components/CaseCard';
import NewInvestigationModal from '../components/NewInvestigationModal';
import { api, MOCK_CASES } from '../api/client';
import { computeSLA } from '../utils/sla';
import { useWebSocket } from '../hooks/useWebSocket';

const TYPES   = ['ALL', 'UPI_FRAUD', 'CARD_FRAUD', 'AML', 'ACCOUNT_TAKEOVER', 'SYNTHETIC_IDENTITY'];
const LEVELS  = ['ALL', 'CRITICAL', 'HIGH', 'MEDIUM', 'LOW'];
const ACTIONS = ['ALL', 'BLOCK', 'ESCALATE', 'REVIEW', 'CLEAR'];
const SLA_OPTS = ['ALL', 'OVERDUE', 'DUE_SOON', 'ON_TRACK', 'RESOLVED'];

const sel = {
  background: 'var(--surface)',
  border: '1px solid var(--border)',
  color: 'var(--text)',
  padding: '7px 10px',
  fontSize: '0.78rem',
  outline: 'none',
};

const inp = {
  ...sel,
  minWidth: 0,
};

const EMPTY_FILTERS = {
  search: '',
  type: 'ALL',
  level: 'ALL',
  action: 'ALL',
  sla: 'ALL',
  dateFrom: '',
  dateTo: '',
  amountMin: '',
  amountMax: '',
};

function activeFilterCount(f) {
  return [
    f.search, f.type !== 'ALL', f.level !== 'ALL', f.action !== 'ALL', f.sla !== 'ALL',
    f.dateFrom, f.dateTo, f.amountMin, f.amountMax,
  ].filter(Boolean).length;
}

const RISK_COLORS_TOAST = {
  CRITICAL: { bg: '#ef444415', border: '#ef444440', text: 'var(--risk-block)' },
  HIGH:     { bg: '#f97316 15', border: '#f9731640', text: '#f97316' },
  MEDIUM:   { bg: '#f59e0b15', border: '#f59e0b40', text: '#f59e0b' },
  LOW:      { bg: 'var(--surface)', border: 'var(--border)', text: 'var(--muted)' },
};

export default function CaseQueue() {
  const [modal, setModal] = useState(false);
  const [expanded, setExpanded] = useState(false);
  const [filters, setFilters] = useState(EMPTY_FILTERS);
  const [liveToasts, setLiveToasts] = useState([]);
  const set = (k, v) => setFilters(f => ({ ...f, [k]: v }));

  // Real-time WebSocket — auto-invalidates ['investigations'] on new cases
  const handleWsMessage = useCallback((msg) => {
    if (msg.type === 'CASE_ADDED') {
      const id = Date.now();
      setLiveToasts(t => [{ id, ...msg }, ...t].slice(0, 4));
      // Auto-dismiss after 10s
      setTimeout(() => setLiveToasts(t => t.filter(x => x.id !== id)), 10_000);
    }
    if (msg.type === 'SLA_OVERDUE') {
      const id = Date.now();
      setLiveToasts(t => [{ id, type: 'SLA_OVERDUE', case_id: msg.case_id, risk_level: msg.risk_level, alert_type: msg.alert_type }, ...t].slice(0, 4));
      setTimeout(() => setLiveToasts(t => t.filter(x => x.id !== id)), 15_000);
    }
  }, []);

  useWebSocket({ onMessage: handleWsMessage });

  const { data: me } = useQuery({ queryKey: ['me'], queryFn: () => api.getMe(), staleTime: 300_000 });

  const { data: apiCases, isError, isLoading } = useQuery({
    queryKey: ['investigations'],
    queryFn: () => api.get('/api/investigations'),
    retry: 1,
    staleTime: 30_000,
  });

  const isDemo = isError || (!isLoading && (!apiCases || apiCases.length === 0));
  const rawCases = useMemo(
    () => (isDemo ? MOCK_CASES : (apiCases || [])).map(computeSLA),
    [isDemo, apiCases],
  );

  const cases = useMemo(() => {
    const s = filters.search.trim().toLowerCase();
    const amtMin = filters.amountMin ? parseFloat(filters.amountMin) : null;
    const amtMax = filters.amountMax ? parseFloat(filters.amountMax) : null;
    const df = filters.dateFrom ? new Date(filters.dateFrom) : null;
    const dt = filters.dateTo ? new Date(filters.dateTo + 'T23:59:59') : null;

    return rawCases.filter(c => {
      if (filters.type   !== 'ALL' && c.alert_type         !== filters.type)   return false;
      if (filters.level  !== 'ALL' && c.risk_level          !== filters.level)  return false;
      if (filters.action !== 'ALL' && c.recommended_action  !== filters.action) return false;
      if (filters.sla    !== 'ALL' && c.sla_status          !== filters.sla)    return false;
      if (amtMin !== null && (c.amount || 0) < amtMin) return false;
      if (amtMax !== null && (c.amount || 0) > amtMax) return false;
      const ts = c.received_at || c.created_at;
      if (df && ts && new Date(ts) < df) return false;
      if (dt && ts && new Date(ts) > dt) return false;
      if (s) {
        const hay = [
          c.case_id, c.investigation_narrative, c.alert_type, c.risk_level,
          ...(c.flags || []),
        ].join(' ').toLowerCase();
        if (!hay.includes(s)) return false;
      }
      return true;
    });
  }, [rawCases, filters]);

  const criticalCount  = rawCases.filter(c => c.risk_level === 'CRITICAL').length;
  const overdueCount   = rawCases.filter(c => c.sla_status === 'OVERDUE').length;
  const dueSoonCount   = rawCases.filter(c => c.sla_status === 'DUE_SOON').length;
  const activeCount    = activeFilterCount(filters);
  const clearFilters   = () => setFilters(EMPTY_FILTERS);

  return (
    <div style={{ display: 'flex' }}>
      <Sidebar analyst={{ name: me?.full_name || me?.email || 'Analyst' }} />
      <main style={{ marginLeft: 220, flex: 1, padding: '24px 28px', minHeight: '100vh' }}>

        {/* Live toast notifications from WebSocket */}
        {liveToasts.length > 0 && (
          <div style={{ marginBottom: 10, display: 'flex', flexDirection: 'column', gap: 6 }}>
            {liveToasts.map(toast => {
              const colors = RISK_COLORS_TOAST[toast.risk_level] || RISK_COLORS_TOAST.LOW;
              const isSla = toast.type === 'SLA_OVERDUE';
              return (
                <div
                  key={toast.id}
                  style={{
                    background: colors.bg,
                    border: `1px solid ${colors.border}`,
                    color: colors.text,
                    padding: '7px 14px',
                    fontSize: '0.72rem',
                    letterSpacing: '0.06em',
                    display: 'flex',
                    alignItems: 'center',
                    gap: 10,
                  }}
                >
                  <span style={{ fontSize: '0.6rem', animation: 'pulse 1s infinite' }}>●</span>
                  <span style={{ fontWeight: 700 }}>
                    {isSla ? 'SLA OVERDUE' : 'NEW CASE'}
                  </span>
                  <span style={{ color: 'var(--muted)' }}>·</span>
                  <span>{toast.risk_level} · {toast.alert_type?.replace('_', ' ')}</span>
                  {toast.case_id && (
                    <span style={{ fontFamily: 'monospace', color: 'var(--muted)', fontSize: '0.68rem' }}>
                      {toast.case_id}
                    </span>
                  )}
                  <button
                    onClick={() => setLiveToasts(t => t.filter(x => x.id !== toast.id))}
                    style={{ marginLeft: 'auto', background: 'none', border: 'none', color: 'var(--muted)', cursor: 'pointer', fontSize: '0.9rem', lineHeight: 1, padding: '0 4px' }}
                    aria-label="Dismiss"
                  >
                    ×
                  </button>
                </div>
              );
            })}
          </div>
        )}

        {/* Demo banner */}
        {isDemo && !isLoading && (
          <div style={{ background: '#f59e0b15', border: '1px solid #f59e0b40', color: '#f59e0b', padding: '5px 12px', fontSize: '0.7rem', letterSpacing: '0.1em', marginBottom: 14, display: 'inline-flex', alignItems: 'center', gap: 6 }}>
            <span style={{ fontSize: '0.6rem' }}>●</span> DEMO DATA
          </div>
        )}

        {/* SLA alert banners */}
        {overdueCount > 0 && (
          <div
            onClick={() => set('sla', filters.sla === 'OVERDUE' ? 'ALL' : 'OVERDUE')}
            style={{ background: '#ef444415', border: '1px solid #ef444440', color: 'var(--risk-block)', padding: '6px 14px', fontSize: '0.72rem', letterSpacing: '0.08em', marginBottom: 8, cursor: 'pointer', display: 'flex', alignItems: 'center', gap: 8 }}
          >
            <span style={{ fontSize: '0.6rem' }}>●</span>
            {overdueCount} case{overdueCount !== 1 ? 's' : ''} overdue SLA — click to filter
          </div>
        )}
        {dueSoonCount > 0 && overdueCount === 0 && (
          <div
            onClick={() => set('sla', filters.sla === 'DUE_SOON' ? 'ALL' : 'DUE_SOON')}
            style={{ background: '#f59e0b10', border: '1px solid #f59e0b40', color: '#f59e0b', padding: '6px 14px', fontSize: '0.72rem', letterSpacing: '0.08em', marginBottom: 8, cursor: 'pointer', display: 'flex', alignItems: 'center', gap: 8 }}
          >
            <span style={{ fontSize: '0.6rem' }}>●</span>
            {dueSoonCount} case{dueSoonCount !== 1 ? 's' : ''} approaching SLA deadline — click to filter
          </div>
        )}

        {/* Header */}
        <div style={{ display: 'flex', alignItems: 'flex-start', justifyContent: 'space-between', marginBottom: 16 }}>
          <div>
            <div style={{ fontWeight: 700, fontSize: '1rem', letterSpacing: '0.08em', textTransform: 'uppercase' }}>Case Queue</div>
            <div style={{ fontSize: '0.72rem', color: 'var(--muted)', marginTop: 3 }}>
              {cases.length} of {rawCases.length} cases
              {criticalCount > 0 && <span style={{ color: 'var(--risk-block)', marginLeft: 6 }}>· {criticalCount} critical</span>}
            </div>
          </div>
          <button
            onClick={() => setModal(true)}
            style={{ background: 'var(--cyan)', border: 'none', color: '#000', padding: '8px 18px', fontWeight: 700, letterSpacing: '0.08em', fontSize: '0.8rem', cursor: 'pointer' }}
          >
            + NEW INVESTIGATION
          </button>
        </div>

        {/* Filter bar — primary row */}
        <div style={{ display: 'flex', gap: 8, marginBottom: 6, flexWrap: 'wrap', alignItems: 'center' }}>
          {/* Search */}
          <input
            value={filters.search}
            onChange={e => set('search', e.target.value)}
            placeholder="Search narrative, flags, case ID…"
            style={{ ...inp, flex: '1 1 200px' }}
          />
          <select value={filters.type}   onChange={e => set('type', e.target.value)}   style={sel}>{TYPES.map(t => <option key={t}>{t}</option>)}</select>
          <select value={filters.level}  onChange={e => set('level', e.target.value)}  style={sel}>{LEVELS.map(l => <option key={l}>{l}</option>)}</select>
          <select value={filters.action} onChange={e => set('action', e.target.value)} style={sel}>{ACTIONS.map(a => <option key={a}>{a}</option>)}</select>

          {/* SLA filter */}
          <select value={filters.sla} onChange={e => set('sla', e.target.value)} style={{ ...sel, color: filters.sla === 'OVERDUE' ? 'var(--risk-block)' : filters.sla === 'DUE_SOON' ? '#f59e0b' : 'var(--text)' }}>
            {SLA_OPTS.map(s => <option key={s} value={s}>{s === 'ALL' ? 'SLA: ALL' : `SLA: ${s}`}</option>)}
          </select>

          {/* More filters toggle */}
          <button
            onClick={() => setExpanded(e => !e)}
            style={{ background: expanded ? 'var(--surface2)' : 'none', border: '1px solid var(--border)', color: 'var(--muted)', padding: '7px 12px', fontSize: '0.75rem', cursor: 'pointer', whiteSpace: 'nowrap' }}
          >
            {expanded ? '▲ Less' : '▼ Date / Amount'}
          </button>

          {/* Clear */}
          {activeCount > 0 && (
            <button
              onClick={clearFilters}
              style={{ background: 'none', border: '1px solid var(--border)', color: 'var(--muted)', padding: '7px 12px', fontSize: '0.75rem', cursor: 'pointer', whiteSpace: 'nowrap' }}
            >
              Clear ({activeCount})
            </button>
          )}
        </div>

        {/* Expanded: date + amount range */}
        {expanded && (
          <div style={{ display: 'flex', gap: 8, marginBottom: 10, flexWrap: 'wrap', alignItems: 'center', padding: '10px 14px', background: 'var(--surface)', border: '1px solid var(--border)' }}>
            <span style={{ fontSize: '0.68rem', color: 'var(--muted)', letterSpacing: '0.1em', whiteSpace: 'nowrap' }}>DATE</span>
            <input type="date" value={filters.dateFrom} onChange={e => set('dateFrom', e.target.value)} style={{ ...inp, colorScheme: 'dark' }} />
            <span style={{ fontSize: '0.72rem', color: 'var(--muted)' }}>to</span>
            <input type="date" value={filters.dateTo} onChange={e => set('dateTo', e.target.value)} style={{ ...inp, colorScheme: 'dark' }} />

            <span style={{ fontSize: '0.68rem', color: 'var(--muted)', letterSpacing: '0.1em', marginLeft: 16, whiteSpace: 'nowrap' }}>AMOUNT (₹)</span>
            <input type="number" placeholder="Min" value={filters.amountMin} onChange={e => set('amountMin', e.target.value)} style={{ ...inp, width: 100 }} />
            <span style={{ fontSize: '0.72rem', color: 'var(--muted)' }}>to</span>
            <input type="number" placeholder="Max" value={filters.amountMax} onChange={e => set('amountMax', e.target.value)} style={{ ...inp, width: 100 }} />
          </div>
        )}

        {/* Results */}
        {isLoading
          ? <div style={{ textAlign: 'center', color: 'var(--muted)', marginTop: 60, fontSize: '0.88rem' }}>Loading cases...</div>
          : cases.length === 0
            ? <div style={{ textAlign: 'center', color: 'var(--muted)', marginTop: 60, fontSize: '0.88rem' }}>No cases match the current filters.</div>
            : cases.map(c => <CaseCard key={c.case_id} c={c} />)
        }

        {modal && <NewInvestigationModal onClose={() => setModal(false)} />}
      </main>
    </div>
  );
}
