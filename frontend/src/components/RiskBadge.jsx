const COLORS = { BLOCK:'var(--risk-block)', ESCALATE:'var(--risk-escalate)', REVIEW:'var(--risk-review)', CLEAR:'var(--risk-clear)', CRITICAL:'var(--risk-block)', HIGH:'var(--risk-escalate)', MEDIUM:'var(--risk-review)', LOW:'var(--risk-clear)' };
export default function RiskBadge({ level }) {
  const c = COLORS[level] || 'var(--muted)';
  return <span style={{ background:`${c}22`, color:c, border:`1px solid ${c}44`, padding:'2px 10px', fontSize:'0.7rem', fontWeight:700, letterSpacing:'0.12em', textTransform:'uppercase', whiteSpace:'nowrap' }}>{level}</span>;
}
