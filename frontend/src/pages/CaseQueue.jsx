import { useState } from 'react';
import { useQuery } from '@tanstack/react-query';
import Sidebar from '../components/Sidebar';
import CaseCard from '../components/CaseCard';
import NewInvestigationModal from '../components/NewInvestigationModal';
import { api, MOCK_CASES } from '../api/client';

const TYPES = ['ALL','UPI_FRAUD','CARD_FRAUD','AML','ACCOUNT_TAKEOVER','SYNTHETIC_IDENTITY'];
const LEVELS = ['ALL','CRITICAL','HIGH','MEDIUM','LOW'];
const ACTIONS = ['ALL','BLOCK','ESCALATE','REVIEW','CLEAR'];
const sel = { background:'var(--surface)', border:'1px solid var(--border)', color:'var(--text)', padding:'7px 10px', fontSize:'0.78rem', outline:'none' };

export default function CaseQueue() {
  const [modal, setModal] = useState(false);
  const [tf, setTf] = useState('ALL');
  const [lf, setLf] = useState('ALL');
  const [af, setAf] = useState('ALL');

  const { data: apiCases, isError, isLoading } = useQuery({
    queryKey: ['investigations'],
    queryFn: () => api.get('/api/investigations'),
    retry: 1,
    staleTime: 30_000,
  });

  const isDemo = isError || (!isLoading && (!apiCases || apiCases.length === 0));
  const rawCases = isDemo ? MOCK_CASES : (apiCases || []);

  const cases = rawCases.filter(c =>
    (tf === 'ALL' || c.alert_type === tf) &&
    (lf === 'ALL' || c.risk_level === lf) &&
    (af === 'ALL' || c.recommended_action === af)
  );

  const criticalCount = rawCases.filter(c => c.risk_level === 'CRITICAL').length;

  return (
    <div style={{ display:'flex' }}>
      <Sidebar analyst={{ name:'Fraud Analyst' }} />
      <main style={{ marginLeft:220, flex:1, padding:'24px 28px', minHeight:'100vh' }}>
        {isDemo && !isLoading && (
          <div style={{ background:'#f59e0b15', border:'1px solid #f59e0b40', color:'#f59e0b', padding:'5px 12px', fontSize:'0.7rem', letterSpacing:'0.1em', marginBottom:14, display:'inline-flex', alignItems:'center', gap:6 }}>
            <span style={{ fontSize:'0.6rem' }}>●</span> DEMO DATA
          </div>
        )}
        <div style={{ display:'flex', alignItems:'flex-start', justifyContent:'space-between', marginBottom:20 }}>
          <div>
            <div style={{ fontWeight:700, fontSize:'1rem', letterSpacing:'0.08em', textTransform:'uppercase' }}>Case Queue</div>
            <div style={{ fontSize:'0.72rem', color:'var(--muted)', marginTop:3 }}>{cases.length} active · {criticalCount} critical</div>
          </div>
          <button onClick={() => setModal(true)} style={{ background:'var(--cyan)', border:'none', color:'#000', padding:'8px 18px', fontWeight:700, letterSpacing:'0.08em', fontSize:'0.8rem' }}>+ NEW INVESTIGATION</button>
        </div>
        <div style={{ display:'flex', gap:8, marginBottom:16, flexWrap:'wrap' }}>
          <select value={tf} onChange={e => setTf(e.target.value)} style={sel}>{TYPES.map(t => <option key={t}>{t}</option>)}</select>
          <select value={lf} onChange={e => setLf(e.target.value)} style={sel}>{LEVELS.map(l => <option key={l}>{l}</option>)}</select>
          <select value={af} onChange={e => setAf(e.target.value)} style={sel}>{ACTIONS.map(a => <option key={a}>{a}</option>)}</select>
          {(tf !== 'ALL' || lf !== 'ALL' || af !== 'ALL') && (
            <button onClick={() => { setTf('ALL'); setLf('ALL'); setAf('ALL'); }} style={{ background:'none', border:'1px solid var(--border)', color:'var(--muted)', padding:'7px 12px', fontSize:'0.75rem' }}>Clear filters</button>
          )}
        </div>
        {isLoading
          ? <div style={{ textAlign:'center', color:'var(--muted)', marginTop:60, fontSize:'0.88rem' }}>Loading cases...</div>
          : cases.length === 0
            ? <div style={{ textAlign:'center', color:'var(--muted)', marginTop:60, fontSize:'0.88rem' }}>No cases match the current filters.</div>
            : cases.map(c => <CaseCard key={c.case_id} c={c} />)
        }
        {modal && <NewInvestigationModal onClose={() => setModal(false)} />}
      </main>
    </div>
  );
}
