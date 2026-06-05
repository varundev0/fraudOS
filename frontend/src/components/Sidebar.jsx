import { NavLink } from 'react-router-dom';
const NAV = [['/', 'Queue'], ['/reports', 'Reports'], ['/settings', 'Settings']];
export default function Sidebar({ analyst }) {
  return (
    <aside style={{ width:220, background:'var(--surface)', borderRight:'1px solid var(--border)', display:'flex', flexDirection:'column', height:'100vh', position:'fixed', left:0, top:0, zIndex:50 }}>
      <div style={{ padding:'22px 20px 18px', borderBottom:'1px solid var(--border)' }}>
        <div style={{ fontFamily:'monospace', fontWeight:900, fontSize:'1.05rem', letterSpacing:'0.2em', color:'var(--cyan)' }}>FRAUDOS</div>
        <div style={{ fontSize:'0.6rem', color:'var(--muted)', letterSpacing:'0.2em', marginTop:3, textTransform:'uppercase' }}>Investigation Platform</div>
      </div>
      <nav style={{ flex:1, padding:'12px 0' }}>
        {NAV.map(([to, label]) => (
          <NavLink key={to} to={to} end={to==='/'} style={({ isActive }) => ({ display:'block', padding:'10px 20px', fontSize:'0.82rem', fontWeight:500, letterSpacing:'0.05em', color: isActive ? 'var(--cyan)' : 'var(--muted)', background: isActive ? '#06b6d410' : 'transparent', borderLeft: isActive ? '2px solid var(--cyan)' : '2px solid transparent', textDecoration:'none', transition:'all 0.15s' })}>{label}</NavLink>
        ))}
      </nav>
      <div style={{ padding:'14px 20px', borderTop:'1px solid var(--border)' }}>
        <div style={{ fontSize:'0.75rem', color:'var(--text)', fontWeight:600 }}>{analyst?.name || 'Analyst'}</div>
        <div style={{ fontSize:'0.62rem', color:'var(--muted)', marginTop:2, letterSpacing:'0.05em' }}>Fraud Investigator</div>
      </div>
    </aside>
  );
}
