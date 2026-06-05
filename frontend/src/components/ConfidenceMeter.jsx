export default function ConfidenceMeter({ value }) {
  const pct = Math.round((value || 0) * 100);
  const color = pct >= 85 ? 'var(--risk-clear)' : pct >= 65 ? 'var(--cyan)' : 'var(--risk-escalate)';
  return (
    <div style={{ marginTop: 12 }}>
      <div style={{ display:'flex', justifyContent:'space-between', marginBottom:4 }}>
        <span style={{ fontSize:'0.65rem', color:'var(--muted)', letterSpacing:'0.15em', textTransform:'uppercase' }}>Confidence</span>
        <span style={{ fontSize:'0.75rem', fontWeight:700, color }}>{pct}%</span>
      </div>
      <div style={{ background:'var(--border)', height:3 }}>
        <div style={{ background:color, width:`${pct}%`, height:'100%', transition:'width 0.6s ease' }} />
      </div>
    </div>
  );
}
