import { useLocation, useParams, useNavigate } from 'react-router-dom';
import { useState } from 'react';
import { useQuery } from '@tanstack/react-query';
import { MOCK_CASES, api } from '../api/client';
import Sidebar from '../components/Sidebar';
import RiskBadge from '../components/RiskBadge';
import AlertTypeBadge from '../components/AlertTypeBadge';
import ConfidenceMeter from '../components/ConfidenceMeter';

const DECISION_BTNS = [
  { a:'CLEAR',    c:'var(--risk-clear)' },
  { a:'REVIEW',   c:'var(--risk-review)' },
  { a:'ESCALATE', c:'var(--risk-escalate)' },
  { a:'BLOCK',    c:'var(--risk-block)' },
];
const card = (extra={}) => ({ background:'var(--surface)', border:'1px solid var(--border)', padding:'18px 20px', marginBottom:10, ...extra });
const lbl = { fontSize:'0.62rem', color:'var(--muted)', letterSpacing:'0.18em', textTransform:'uppercase', marginBottom:8, display:'block' };

const TOKEN_TYPE_LABELS = {
  USR: 'Name', MER: 'Merchant', ADDR: 'Address', EML: 'Email', UPI: 'UPI ID', PHN: 'Phone',
};

function PiiRevealPanel({ caseId }) {
  const [revealed, setRevealed] = useState(false);
  const [piiData, setPiiData] = useState(null);
  const [error, setError] = useState('');
  const [loading, setLoading] = useState(false);

  const reveal = async () => {
    setLoading(true);
    setError('');
    try {
      const data = await api.get(`/api/investigations/${caseId}/pii`);
      setPiiData(data);
      setRevealed(true);
    } catch (e) {
      setError(e.message.includes('404')
        ? 'No PII map stored for this case'
        : 'PII access denied or unavailable');
    } finally {
      setLoading(false);
    }
  };

  return (
    <div style={card({ borderLeft: '2px solid var(--risk-block)' })}>
      <div style={{ display:'flex', justifyContent:'space-between', alignItems:'center' }}>
        <span style={{ ...lbl, marginBottom: 0 }}>
          PII Re-identification <span style={{ color:'var(--risk-block)', fontSize:'0.58rem' }}>· PRIVILEGED · AUDIT-LOGGED</span>
        </span>
        {!revealed && (
          <button onClick={reveal} disabled={loading} style={{ background:'transparent', border:'1px solid var(--risk-block)', color:'var(--risk-block)', padding:'5px 14px', fontWeight:700, letterSpacing:'0.08em', fontSize:'0.72rem', cursor:'pointer' }}>
            {loading ? 'DECRYPTING...' : 'REVEAL PII'}
          </button>
        )}
        {revealed && (
          <button onClick={() => { setRevealed(false); setPiiData(null); }} style={{ background:'transparent', border:'1px solid var(--border)', color:'var(--muted)', padding:'5px 14px', fontWeight:600, letterSpacing:'0.08em', fontSize:'0.72rem', cursor:'pointer' }}>
            HIDE
          </button>
        )}
      </div>
      {error && <div style={{ fontSize:'0.78rem', color:'var(--risk-block)', marginTop: 10 }}>{error}</div>}
      {revealed && piiData && (
        <div style={{ marginTop: 12 }}>
          {Object.entries(piiData.pii_map).map(([token, original]) => (
            <div key={token} style={{ display:'flex', alignItems:'center', gap:12, padding:'7px 0', borderBottom:'1px solid var(--border)', fontSize:'0.8rem' }}>
              <span style={{ background:'var(--surface2)', border:'1px solid var(--border)', padding:'2px 8px', fontSize:'0.65rem', color:'var(--muted)', minWidth:58, textAlign:'center' }}>
                {TOKEN_TYPE_LABELS[token.split('-')[0]] || token.split('-')[0]}
              </span>
              <span style={{ fontFamily:'monospace', fontSize:'0.72rem', color:'var(--muted)' }}>{token}</span>
              <span style={{ marginLeft:'auto', fontWeight:600 }}>{original}</span>
            </div>
          ))}
        </div>
      )}
    </div>
  );
}

export default function CaseDetail() {
  const { caseId } = useParams();
  const { state } = useLocation();
  const nav = useNavigate();
  const hasStateData = !!state?.caseData;

  const { data: apiCase, isLoading } = useQuery({
    queryKey: ['investigation', caseId],
    queryFn: () => api.get(`/api/investigations/${caseId}`),
    enabled: !hasStateData,
    retry: 1,
    staleTime: 30_000,
  });

  const { data: me } = useQuery({ queryKey: ['me'], queryFn: () => api.getMe(), staleTime: 300_000 });
  const canRevealPii = me?.role === 'ADMIN' || me?.role === 'SUPERVISOR';

  const c = state?.caseData || apiCase || MOCK_CASES.find(x => x.case_id === caseId) || {};
  const [decision, setDecision] = useState('');
  const [notes, setNotes] = useState('');
  const [submitted, setSubmitted] = useState(false);
  const [decisionError, setDecisionError] = useState('');
  const [blockConfirm, setBlockConfirm] = useState(false);

  const fmt = new Intl.NumberFormat('en-IN', { style:'currency', currency:'INR', maximumFractionDigits:0 });
  const riskColor = { CRITICAL:'var(--risk-block)', HIGH:'var(--risk-escalate)', MEDIUM:'var(--risk-review)', LOW:'var(--risk-clear)' }[c.risk_level] || 'var(--muted)';

  const submitDecision = async () => {
    if (!decision) return;
    if (decision === 'BLOCK' && !blockConfirm) {
      setBlockConfirm(true);
      return;
    }
    setBlockConfirm(false);
    setDecisionError('');
    try {
      await api.post(`/api/investigations/${c.case_id}/decision`, { decision, notes });
      setSubmitted(true);
    } catch {
      setDecisionError('Failed to submit decision — please retry');
    }
  };

  const handleDecisionSelect = (a) => {
    setDecision(a);
    setBlockConfirm(false);
  };

  const exportSar = async () => {
    try {
      const text = await api.getText(`/api/investigations/${c.case_id}/sar`);
      const blob = new Blob([text], { type: 'text/plain' });
      const url = URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url;
      a.download = `SAR_DRAFT_${c.case_id}.txt`;
      a.click();
      URL.revokeObjectURL(url);
    } catch {
      setDecisionError('Failed to export SAR — case may not be persisted yet');
    }
  };

  if (isLoading && !hasStateData) return (
    <div style={{ display:'flex' }}>
      <Sidebar analyst={{ name:'Fraud Analyst' }} />
      <main style={{ marginLeft:220, flex:1, padding:'40px 28px', color:'var(--muted)' }}>Loading case...</main>
    </div>
  );

  if (!c.case_id) return (
    <div style={{ display:'flex' }}>
      <Sidebar analyst={{ name:'Fraud Analyst' }} />
      <main style={{ marginLeft:220, flex:1, padding:'40px 28px', color:'var(--muted)' }}>Case not found. <button onClick={() => nav('/')} style={{ background:'none', border:'none', color:'var(--cyan)', cursor:'pointer' }}>← Back</button></main>
    </div>
  );

  return (
    <div style={{ display:'flex' }}>
      <Sidebar analyst={{ name:'Fraud Analyst' }} />
      <main style={{ marginLeft:220, flex:1, padding:'24px 28px', paddingBottom:110, minHeight:'100vh' }}>
        <button onClick={() => nav('/')} style={{ background:'none', border:'none', color:'var(--muted)', fontSize:'0.8rem', marginBottom:18, letterSpacing:'0.05em', cursor:'pointer' }}>← Case Queue</button>

        {/* Header */}
        <div style={{ display:'flex', alignItems:'center', gap:10, marginBottom:18, flexWrap:'wrap' }}>
          <span style={{ fontFamily:'monospace', fontWeight:700, fontSize:'0.95rem' }}>{c.case_id}</span>
          <AlertTypeBadge type={c.alert_type} />
          <RiskBadge level={c.risk_level} />
          <RiskBadge level={c.recommended_action} />
          {c.constitutional_check_passed !== undefined && (
            <span style={{ fontSize:'0.65rem', color: c.constitutional_check_passed ? 'var(--risk-clear)' : 'var(--risk-block)', marginLeft:4 }}>
              {c.constitutional_check_passed ? '● Constitutional check passed' : '● Constitutional check failed'}
            </span>
          )}
          {c.processing_time_ms && <span style={{ fontSize:'0.7rem', color:'var(--muted)', marginLeft:'auto' }}>{c.processing_time_ms}ms · {c.model_used || 'claude-opus-4-6'}</span>}
        </div>

        {/* KPI row */}
        <div style={{ display:'grid', gridTemplateColumns:'1fr 1fr', gap:10, marginBottom:10 }}>
          <div style={card()}>
            <span style={lbl}>Risk Score</span>
            <div style={{ fontSize:'3.5rem', fontWeight:900, color:riskColor, lineHeight:1, fontVariantNumeric:'tabular-nums' }}>
              {c.risk_score}<span style={{ fontSize:'1rem', color:'var(--muted)', fontWeight:400 }}>/100</span>
            </div>
          </div>
          <div style={card()}>
            <span style={lbl}>Transaction Amount</span>
            <div style={{ fontSize:'1.8rem', fontWeight:700, marginBottom:4 }}>{fmt.format(c.amount)}</div>
            <ConfidenceMeter value={c.confidence || 0.8} />
          </div>
        </div>

        {/* Entity Profile */}
        {c.entity_profile && (
          <div style={card()}>
            <span style={lbl}>Entity Profile</span>
            <p style={{ fontSize:'0.88rem', marginBottom:10, lineHeight:1.5 }}>{c.entity_profile.summary}</p>
            <div style={{ display:'flex', flexWrap:'wrap', gap:6 }}>
              {c.entity_profile.risk_indicators?.map((r,i) => (
                <span key={i} style={{ background:'#ef444415', color:'var(--risk-block)', border:'1px solid #ef444430', padding:'2px 9px', fontSize:'0.7rem' }}>{r}</span>
              ))}
            </div>
          </div>
        )}

        {/* Transaction Pattern */}
        {c.transaction_pattern && (
          <div style={card()}>
            <span style={lbl}>Transaction Pattern</span>
            <div style={{ fontSize:'0.82rem', color:'var(--muted)', marginBottom:10 }}>Pattern type: <strong style={{ color:'var(--text)' }}>{c.transaction_pattern.pattern_type}</strong></div>
            {c.transaction_pattern.anomalies?.map((a,i) => (
              <div key={i} style={{ fontSize:'0.83rem', padding:'6px 0', borderBottom:'1px solid var(--border)', color:'var(--text)' }}>⚠ {a}</div>
            ))}
            {c.transaction_pattern.velocity_assessment && (
              <div style={{ fontSize:'0.78rem', color:'var(--muted)', marginTop:8 }}>{c.transaction_pattern.velocity_assessment}</div>
            )}
          </div>
        )}

        {/* Risk Assessment */}
        {c.risk_assessment && (
          <div style={card({ borderLeft:'2px solid var(--risk-escalate)' })}>
            <span style={lbl}>Risk Assessment</span>
            <p style={{ fontSize:'0.88rem', lineHeight:1.65 }}>{c.risk_assessment}</p>
          </div>
        )}

        {/* Flags */}
        {c.flags?.length > 0 && (
          <div style={card()}>
            <span style={lbl}>Flags</span>
            <div style={{ display:'flex', flexWrap:'wrap', gap:6 }}>
              {c.flags.map((f,i) => (
                <span key={i} style={{ background:'var(--surface2)', border:'1px solid var(--border)', padding:'3px 10px', fontSize:'0.75rem' }}>{f}</span>
              ))}
            </div>
          </div>
        )}

        {/* Investigation Narrative */}
        {c.investigation_narrative && (
          <div style={card({ borderLeft:'2px solid var(--purple)' })}>
            <span style={lbl}>Investigation Narrative <span style={{ color:'var(--purple)', fontSize:'0.58rem' }}>· AI GENERATED</span></span>
            <p style={{ fontSize:'0.88rem', lineHeight:1.7 }}>{c.investigation_narrative}</p>
          </div>
        )}

        {/* PII re-identification (ADMIN / SUPERVISOR only) */}
        {canRevealPii && <PiiRevealPanel caseId={c.case_id} />}
      </main>

      {/* Decision + SAR panel */}
      <div style={{ position:'fixed', bottom:0, left:220, right:0, background:'var(--surface)', borderTop:'1px solid var(--border)', padding:'12px 24px', display:'flex', gap:10, alignItems:'center', zIndex:50, flexWrap:'wrap' }}>
        {submitted
          ? <span style={{ color:'var(--risk-clear)', fontWeight:600, fontSize:'0.85rem', letterSpacing:'0.05em' }}>✓ Decision recorded</span>
          : <>
            {DECISION_BTNS.map(({ a, c: col }) => (
              <button key={a} onClick={() => handleDecisionSelect(a)} style={{ background: decision === a ? col : 'transparent', border:`1px solid ${col}`, color: decision === a ? '#000' : col, padding:'7px 16px', fontWeight:700, letterSpacing:'0.08em', fontSize:'0.78rem', transition:'all 0.15s' }}>{a}</button>
            ))}
            <textarea value={notes} onChange={e => setNotes(e.target.value)} placeholder="Analyst notes..." style={{ flex:1, minWidth:120, background:'var(--surface2)', border:'1px solid var(--border)', color:'var(--text)', padding:'7px 12px', fontSize:'0.83rem', resize:'none', height:36, outline:'none' }} />
            {blockConfirm && (
              <span style={{ color:'var(--risk-block)', fontSize:'0.78rem', fontWeight:600, whiteSpace:'nowrap' }}>
                ⚠ BLOCK is irreversible — click Submit again to confirm.
              </span>
            )}
            <button onClick={submitDecision} disabled={!decision} style={{ background: decision ? (blockConfirm ? 'var(--risk-block)' : 'var(--cyan)') : 'var(--surface2)', border:'none', color: decision ? '#000' : 'var(--muted)', padding:'8px 18px', fontWeight:700, letterSpacing:'0.08em', fontSize:'0.8rem', whiteSpace:'nowrap' }}>
              {blockConfirm ? 'CONFIRM BLOCK' : 'SUBMIT DECISION'}
            </button>
          </>
        }
        <button onClick={exportSar} style={{ background:'transparent', border:'1px solid var(--border)', color:'var(--muted)', padding:'7px 14px', fontWeight:600, letterSpacing:'0.06em', fontSize:'0.75rem', whiteSpace:'nowrap' }}>EXPORT SAR DRAFT</button>
        {decisionError && <span style={{ color:'var(--risk-block)', fontSize:'0.78rem' }}>{decisionError}</span>}
      </div>
    </div>
  );
}
