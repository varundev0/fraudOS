import { useNavigate } from 'react-router-dom';
import RiskBadge from './RiskBadge';
import AlertTypeBadge from './AlertTypeBadge';
export default function CaseCard({ c }) {
  const nav = useNavigate();
  const fmt = new Intl.NumberFormat('en-IN', { style:'currency', currency:'INR', maximumFractionDigits:0 });
  const time = new Date(c.received_at).toLocaleTimeString('en-IN', { hour:'2-digit', minute:'2-digit' });
  const date = new Date(c.received_at).toLocaleDateString('en-IN', { day:'numeric', month:'short' });
  return (
    <div
      onClick={() => nav(`/case/${c.case_id}`, { state: { caseData: c } })}
      style={{ background:'var(--surface)', border:'1px solid var(--border)', padding:'16px 20px', marginBottom:8, cursor:'pointer', transition:'border-color 0.15s, background 0.15s' }}
      onMouseEnter={e => { e.currentTarget.style.borderColor='var(--cyan)'; e.currentTarget.style.background='var(--surface2)'; }}
      onMouseLeave={e => { e.currentTarget.style.borderColor='var(--border)'; e.currentTarget.style.background='var(--surface)'; }}
    >
      <div style={{ display:'flex', alignItems:'center', gap:8, marginBottom:10, flexWrap:'wrap' }}>
        <span style={{ fontFamily:'monospace', fontSize:'0.78rem', color:'var(--muted)', marginRight:2 }}>{c.case_id}</span>
        <AlertTypeBadge type={c.alert_type} />
        <RiskBadge level={c.risk_level} />
        <span style={{ marginLeft:'auto', fontSize:'0.7rem', color:'var(--muted)' }}>{date} · {time}</span>
      </div>
      <div style={{ display:'flex', alignItems:'center', gap:12, marginBottom:10 }}>
        <span style={{ fontSize:'1.25rem', fontWeight:700 }}>{fmt.format(c.amount)}</span>
        <RiskBadge level={c.recommended_action} />
        {c.flags?.slice(0,2).map((f,i) => (
          <span key={i} style={{ fontSize:'0.68rem', color:'var(--muted)', background:'var(--surface2)', border:'1px solid var(--border)', padding:'1px 7px' }}>{f}</span>
        ))}
      </div>
      <p style={{ fontSize:'0.82rem', color:'var(--muted)', lineHeight:1.5, display:'-webkit-box', WebkitLineClamp:2, WebkitBoxOrient:'vertical', overflow:'hidden' }}>{c.investigation_narrative}</p>
    </div>
  );
}
