import { useState } from 'react';
import { api } from '../api/client';
import { useNavigate } from 'react-router-dom';
const TYPES = ['UPI_FRAUD','CARD_FRAUD','AML','ACCOUNT_TAKEOVER','SYNTHETIC_IDENTITY'];
const inp = { background:'var(--surface2)', border:'1px solid var(--border)', color:'var(--text)', padding:'9px 12px', width:'100%', fontSize:'0.88rem', outline:'none' };
export default function NewInvestigationModal({ onClose }) {
  const nav = useNavigate();
  const [form, setForm] = useState({ alert_type:'UPI_FRAUD', amount:'', transaction_id:'', rule_trigger:'', entity_data:'{\n  "name": "",\n  "phone": ""\n}' });
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState('');
  const set = k => e => setForm(f => ({...f, [k]: e.target.value}));
  const submit = async () => {
    setLoading(true); setError('');
    try {
      const body = { alert: { alert_type:form.alert_type, amount:parseFloat(form.amount), transaction_id:form.transaction_id || `TXN-${Date.now()}`, rule_trigger:form.rule_trigger, entity_data:JSON.parse(form.entity_data), currency:'INR' }};
      const res = await api.post('/api/investigate', body);
      if (res.success) { nav(`/case/${res.report.case_id}`, { state:{ caseData:res.report } }); onClose(); }
      else setError(res.error || 'Investigation failed');
    } catch(e) { setError(e.message || 'Request failed'); }
    setLoading(false);
  };
  return (
    <div style={{ position:'fixed', inset:0, background:'rgba(0,0,0,0.85)', display:'flex', alignItems:'center', justifyContent:'center', zIndex:200 }} onClick={e => e.target===e.currentTarget && onClose()}>
      <div style={{ background:'var(--surface)', border:'1px solid var(--border)', width:500, padding:28 }}>
        <div style={{ display:'flex', justifyContent:'space-between', alignItems:'center', marginBottom:20 }}>
          <span style={{ fontWeight:700, letterSpacing:'0.1em', fontSize:'0.9rem' }}>NEW INVESTIGATION</span>
          <button onClick={onClose} style={{ background:'none', border:'none', color:'var(--muted)', fontSize:'1.4rem', lineHeight:1 }}>×</button>
        </div>
        <div style={{ display:'flex', flexDirection:'column', gap:10 }}>
          <select value={form.alert_type} onChange={set('alert_type')} style={inp}>{TYPES.map(t=><option key={t}>{t}</option>)}</select>
          <input placeholder="Amount (INR)" value={form.amount} onChange={set('amount')} style={inp} type="number" />
          <input placeholder="Transaction ID (optional)" value={form.transaction_id} onChange={set('transaction_id')} style={inp} />
          <input placeholder="Rule trigger description" value={form.rule_trigger} onChange={set('rule_trigger')} style={inp} />
          <textarea placeholder="Entity data (JSON)" value={form.entity_data} onChange={set('entity_data')} style={{...inp, height:100, resize:'vertical'}} />
          {error && <div style={{ color:'var(--risk-block)', fontSize:'0.82rem', padding:'6px 0' }}>{error}</div>}
          <button onClick={submit} disabled={loading} style={{ background: loading ? 'var(--surface2)' : 'var(--cyan)', border:'none', color: loading ? 'var(--muted)' : '#000', padding:'11px', fontWeight:700, letterSpacing:'0.1em', fontSize:'0.85rem', marginTop:4 }}>
            {loading ? 'INVESTIGATING...' : 'RUN INVESTIGATION'}
          </button>
        </div>
      </div>
    </div>
  );
}
