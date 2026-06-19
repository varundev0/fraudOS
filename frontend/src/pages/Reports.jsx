import { useMemo } from 'react';
import { useQuery } from '@tanstack/react-query';
import { useNavigate } from 'react-router-dom';
import Sidebar from '../components/Sidebar';
import RiskBadge from '../components/RiskBadge';
import AlertTypeBadge from '../components/AlertTypeBadge';
import { api, MOCK_CASES } from '../api/client';
import { computeSLA, SLA_LABELS } from '../utils/sla';

const card = (extra = {}) => ({
  background: 'var(--surface)',
  border: '1px solid var(--border)',
  padding: '18px 20px',
  ...extra,
});

const lbl = {
  fontSize: '0.62rem',
  color: 'var(--muted)',
  letterSpacing: '0.18em',
  textTransform: 'uppercase',
  marginBottom: 8,
  display: 'block',
};

const ALERT_LABELS = {
  UPI_FRAUD: 'UPI Fraud',
  CARD_FRAUD: 'Card Fraud',
  AML: 'AML',
  ACCOUNT_TAKEOVER: 'Account Takeover',
  SYNTHETIC_IDENTITY: 'Synthetic ID',
};

const RISK_ORDER = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW'];
const ACTION_ORDER = ['BLOCK', 'ESCALATE', 'REVIEW', 'CLEAR'];
const TYPE_ORDER = ['UPI_FRAUD', 'CARD_FRAUD', 'AML', 'ACCOUNT_TAKEOVER', 'SYNTHETIC_IDENTITY'];

const RISK_COLORS = {
  CRITICAL: 'var(--risk-block)',
  HIGH: 'var(--risk-escalate)',
  MEDIUM: 'var(--risk-review)',
  LOW: 'var(--risk-clear)',
};

const ACTION_COLORS = {
  BLOCK: 'var(--risk-block)',
  ESCALATE: 'var(--risk-escalate)',
  REVIEW: 'var(--risk-review)',
  CLEAR: 'var(--risk-clear)',
};

function BarRow({ label, count, total, color, sublabel }) {
  const pct = total > 0 ? (count / total) * 100 : 0;
  return (
    <div style={{ marginBottom: 12 }}>
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 5 }}>
        <span style={{ fontSize: '0.78rem', color: 'var(--text)' }}>{label}</span>
        <span style={{ fontSize: '0.78rem', fontWeight: 700, color: color || 'var(--text)', fontVariantNumeric: 'tabular-nums' }}>
          {count}
          {sublabel && <span style={{ fontSize: '0.65rem', color: 'var(--muted)', fontWeight: 400, marginLeft: 4 }}>{sublabel}</span>}
        </span>
      </div>
      <div style={{ background: 'var(--border)', height: 4 }}>
        <div style={{ background: color || 'var(--cyan)', width: `${pct}%`, height: '100%', transition: 'width 0.5s ease', minWidth: count > 0 ? 3 : 0 }} />
      </div>
    </div>
  );
}

function MetricCard({ label, value, sub, accent }) {
  return (
    <div style={card()}>
      <span style={lbl}>{label}</span>
      <div style={{ fontSize: '2.4rem', fontWeight: 900, color: accent || 'var(--text)', lineHeight: 1, fontVariantNumeric: 'tabular-nums' }}>{value}</div>
      {sub && <div style={{ fontSize: '0.72rem', color: 'var(--muted)', marginTop: 6 }}>{sub}</div>}
    </div>
  );
}

const SLA_ORDER = ['OVERDUE', 'DUE_SOON', 'ON_TRACK', 'RESOLVED'];
const SLA_LABEL_NICE = { OVERDUE: 'Overdue', DUE_SOON: 'Due Soon', ON_TRACK: 'On Track', RESOLVED: 'Resolved' };

export default function Reports() {
  const nav = useNavigate();

  const { data: apiCases, isError, isLoading } = useQuery({
    queryKey: ['investigations'],
    queryFn: () => api.get('/api/investigations'),
    retry: 1,
    staleTime: 30_000,
  });

  const { data: me } = useQuery({ queryKey: ['me'], queryFn: () => api.getMe(), staleTime: 300_000 });

  const isDemo = isError || (!isLoading && (!apiCases || apiCases.length === 0));
  const cases = useMemo(
    () => (isDemo ? MOCK_CASES : (apiCases || [])).map(computeSLA),
    [isDemo, apiCases],
  );

  // Aggregations
  const total = cases.length;
  const avgScore = total > 0
    ? Math.round(cases.reduce((s, c) => s + (c.risk_score || 0), 0) / total)
    : 0;
  const avgConfidence = total > 0
    ? Math.round(cases.reduce((s, c) => s + (c.confidence || 0), 0) / total * 100)
    : 0;
  const criticalCount = cases.filter(c => c.risk_level === 'CRITICAL').length;
  const blockCount = cases.filter(c => c.recommended_action === 'BLOCK').length;

  const byRisk   = Object.fromEntries(RISK_ORDER.map(r   => [r,   cases.filter(c => c.risk_level          === r).length]));
  const byAction = Object.fromEntries(ACTION_ORDER.map(a => [a,   cases.filter(c => c.recommended_action  === a).length]));
  const byType   = Object.fromEntries(TYPE_ORDER.map(t   => [t,   cases.filter(c => c.alert_type          === t).length]));
  const bySla    = Object.fromEntries(SLA_ORDER.map(s    => [s,   cases.filter(c => c.sla_status          === s).length]));
  const resolvedCases = cases.filter(c => c.sla_status === 'RESOLVED');

  const avgScoreByType = TYPE_ORDER.map(t => {
    const group = cases.filter(c => c.alert_type === t);
    return {
      type: t,
      avg: group.length > 0 ? Math.round(group.reduce((s, c) => s + (c.risk_score || 0), 0) / group.length) : 0,
      count: group.length,
    };
  });

  const totalAmount = cases.reduce((s, c) => s + (c.amount || 0), 0);
  const fmtCurrency = new Intl.NumberFormat('en-IN', { style: 'currency', currency: 'INR', maximumFractionDigits: 0 });
  const fmtAmount = (v) => {
    if (v >= 1e7) return `₹${(v / 1e7).toFixed(1)}Cr`;
    if (v >= 1e5) return `₹${(v / 1e5).toFixed(1)}L`;
    return fmtCurrency.format(v);
  };

  const recentCases = [...cases]
    .sort((a, b) => new Date(b.received_at || b.created_at || 0) - new Date(a.received_at || a.created_at || 0))
    .slice(0, 5);

  return (
    <div style={{ display: 'flex' }}>
      <Sidebar analyst={{ name: me?.full_name || me?.email || 'Analyst' }} />
      <main style={{ marginLeft: 220, flex: 1, padding: '24px 28px', minHeight: '100vh' }}>

        {/* Header */}
        <div style={{ display: 'flex', alignItems: 'flex-start', justifyContent: 'space-between', marginBottom: 24 }}>
          <div>
            <div style={{ fontWeight: 700, fontSize: '1rem', letterSpacing: '0.08em', textTransform: 'uppercase' }}>Reports</div>
            <div style={{ fontSize: '0.72rem', color: 'var(--muted)', marginTop: 3 }}>
              Investigation analytics · {total} cases{isDemo && !isLoading ? ' (demo data)' : ''}
            </div>
          </div>
          {isDemo && !isLoading && (
            <div style={{ background: '#f59e0b15', border: '1px solid #f59e0b40', color: '#f59e0b', padding: '5px 12px', fontSize: '0.7rem', letterSpacing: '0.1em', display: 'inline-flex', alignItems: 'center', gap: 6 }}>
              <span style={{ fontSize: '0.6rem' }}>●</span> DEMO DATA
            </div>
          )}
        </div>

        {isLoading ? (
          <div style={{ textAlign: 'center', color: 'var(--muted)', marginTop: 80, fontSize: '0.88rem' }}>Loading reports...</div>
        ) : (
          <>
            {/* KPI row */}
            <div style={{ display: 'grid', gridTemplateColumns: 'repeat(4, 1fr)', gap: 10, marginBottom: 16 }}>
              <MetricCard label="Total Cases" value={total} sub={`Avg score ${avgScore}/100`} />
              <MetricCard label="Critical Cases" value={criticalCount} sub={`${total > 0 ? Math.round(criticalCount / total * 100) : 0}% of total`} accent="var(--risk-block)" />
              <MetricCard label="Block Recommended" value={blockCount} sub={`${total > 0 ? Math.round(blockCount / total * 100) : 0}% of total`} accent="var(--risk-escalate)" />
              <MetricCard label="Total Exposure" value={fmtAmount(totalAmount)} sub={`Avg confidence ${avgConfidence}%`} accent="var(--cyan)" />
            </div>

            {/* Middle row: Risk levels + Actions */}
            <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 10, marginBottom: 10 }}>
              <div style={card()}>
                <span style={lbl}>Cases by Risk Level</span>
                {RISK_ORDER.map(r => (
                  <BarRow key={r} label={r} count={byRisk[r]} total={total} color={RISK_COLORS[r]}
                    sublabel={`${total > 0 ? Math.round(byRisk[r] / total * 100) : 0}%`} />
                ))}
              </div>
              <div style={card()}>
                <span style={lbl}>Cases by Recommended Action</span>
                {ACTION_ORDER.map(a => (
                  <BarRow key={a} label={a} count={byAction[a]} total={total} color={ACTION_COLORS[a]}
                    sublabel={`${total > 0 ? Math.round(byAction[a] / total * 100) : 0}%`} />
                ))}
              </div>
            </div>

            {/* Alert type breakdown */}
            <div style={card({ marginBottom: 10 })}>
              <span style={lbl}>Cases by Alert Type</span>
              <div style={{ display: 'grid', gridTemplateColumns: 'repeat(5, 1fr)', gap: 12 }}>
                {avgScoreByType.map(({ type, avg, count }) => (
                  <div key={type} style={{ textAlign: 'center', padding: '12px 8px', background: 'var(--surface2)', border: '1px solid var(--border)' }}>
                    <div style={{ fontSize: '1.6rem', fontWeight: 900, color: 'var(--cyan)', lineHeight: 1, fontVariantNumeric: 'tabular-nums' }}>{count}</div>
                    <div style={{ fontSize: '0.65rem', color: 'var(--text)', margin: '6px 0 4px', fontWeight: 600 }}>{ALERT_LABELS[type]}</div>
                    <div style={{ fontSize: '0.62rem', color: 'var(--muted)' }}>avg score {avg}</div>
                  </div>
                ))}
              </div>
            </div>

            {/* SLA breakdown */}
            <div style={card({ marginBottom: 10 })}>
              <span style={lbl}>SLA Status</span>
              <div style={{ display: 'grid', gridTemplateColumns: 'repeat(4, 1fr)', gap: 10 }}>
                {SLA_ORDER.map(s => {
                  const meta = SLA_LABELS[s];
                  const count = bySla[s] || 0;
                  const pct = total > 0 ? Math.round(count / total * 100) : 0;
                  return (
                    <div key={s} style={{ textAlign: 'center', padding: '14px 10px', background: 'var(--surface2)', border: `1px solid ${count > 0 && (s === 'OVERDUE' || s === 'DUE_SOON') ? meta.color + '40' : 'var(--border)'}` }}>
                      <div style={{ fontSize: '1.8rem', fontWeight: 900, color: meta.color, lineHeight: 1, fontVariantNumeric: 'tabular-nums' }}>{count}</div>
                      <div style={{ fontSize: '0.65rem', color: meta.color, margin: '6px 0 4px', fontWeight: 700, letterSpacing: '0.1em' }}>{SLA_LABEL_NICE[s]}</div>
                      <div style={{ fontSize: '0.62rem', color: 'var(--muted)' }}>{pct}% of cases</div>
                    </div>
                  );
                })}
              </div>
              {(bySla['OVERDUE'] > 0 || bySla['DUE_SOON'] > 0) && (
                <div style={{ marginTop: 12, padding: '8px 12px', background: '#ef444410', border: '1px solid #ef444430', fontSize: '0.75rem', color: 'var(--risk-block)' }}>
                  {bySla['OVERDUE'] > 0 && <span><strong>{bySla['OVERDUE']}</strong> case{bySla['OVERDUE'] !== 1 ? 's' : ''} past SLA deadline · </span>}
                  {bySla['DUE_SOON'] > 0 && <span><strong>{bySla['DUE_SOON']}</strong> case{bySla['DUE_SOON'] !== 1 ? 's' : ''} expiring soon</span>}
                </div>
              )}
            </div>

            {/* Recent cases */}
            <div style={card()}>
              <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 14 }}>
                <span style={lbl}>Recent Cases</span>
                <button
                  onClick={() => nav('/')}
                  style={{ background: 'none', border: 'none', color: 'var(--cyan)', fontSize: '0.72rem', letterSpacing: '0.08em', cursor: 'pointer' }}
                >
                  VIEW ALL →
                </button>
              </div>
              {recentCases.map(c => {
                const ts = c.received_at || c.created_at;
                const dateStr = ts ? new Date(ts).toLocaleDateString('en-IN', { day: 'numeric', month: 'short' }) : '—';
                const timeStr = ts ? new Date(ts).toLocaleTimeString('en-IN', { hour: '2-digit', minute: '2-digit' }) : '';
                return (
                  <div
                    key={c.case_id}
                    onClick={() => nav(`/case/${c.case_id}`, { state: { caseData: c } })}
                    style={{ display: 'flex', alignItems: 'center', gap: 10, padding: '10px 0', borderBottom: '1px solid var(--border)', cursor: 'pointer' }}
                    onMouseEnter={e => e.currentTarget.style.opacity = '0.75'}
                    onMouseLeave={e => e.currentTarget.style.opacity = '1'}
                  >
                    <span style={{ fontFamily: 'monospace', fontSize: '0.75rem', color: 'var(--muted)', minWidth: 90 }}>{c.case_id}</span>
                    <AlertTypeBadge type={c.alert_type} />
                    <RiskBadge level={c.risk_level} />
                    <span style={{ fontWeight: 700, fontSize: '0.85rem', marginLeft: 4 }}>
                      {new Intl.NumberFormat('en-IN', { style: 'currency', currency: 'INR', maximumFractionDigits: 0 }).format(c.amount)}
                    </span>
                    <span style={{ fontSize: '0.72rem', fontWeight: 700, marginLeft: 'auto', fontVariantNumeric: 'tabular-nums' }}>
                      {c.risk_score}<span style={{ fontWeight: 400, color: 'var(--muted)', fontSize: '0.65rem' }}>/100</span>
                    </span>
                    <span style={{ fontSize: '0.68rem', color: 'var(--muted)', minWidth: 72, textAlign: 'right' }}>{dateStr}{timeStr && ` · ${timeStr}`}</span>
                  </div>
                );
              })}
            </div>
          </>
        )}
      </main>
    </div>
  );
}
