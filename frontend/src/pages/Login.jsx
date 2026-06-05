import { useState } from 'react';
import { useNavigate } from 'react-router-dom';
export default function Login() {
  const [key, setKey] = useState('');
  const nav = useNavigate();
  const connect = () => { if (key.trim()) { sessionStorage.setItem('fraudos_key', key.trim()); nav('/'); }};
  return (
    <div style={{ minHeight:'100vh', display:'flex', flexDirection:'column', alignItems:'center', justifyContent:'center', gap:28 }}>
      <div style={{ textAlign:'center' }}>
        <div style={{ fontFamily:'monospace', fontSize:'clamp(2.5rem,8vw,4rem)', fontWeight:900, letterSpacing:'0.25em', color:'var(--cyan)' }}>FRAUDOS</div>
        <div style={{ fontSize:'0.72rem', color:'var(--muted)', letterSpacing:'0.2em', textTransform:'uppercase', marginTop:6 }}>AI-Native Fraud Investigation Platform</div>
      </div>
      <div style={{ display:'flex', flexDirection:'column', gap:10, width:'min(340px, 90vw)' }}>
        <input value={key} onChange={e=>setKey(e.target.value)} onKeyDown={e=>e.key==='Enter'&&connect()} placeholder="Enter API Key" type="password"
          style={{ background:'var(--surface)', border:'1px solid var(--border)', color:'var(--text)', padding:'13px 16px', fontSize:'0.95rem', outline:'none', width:'100%' }}
          onFocus={e=>e.target.style.borderColor='var(--cyan)'} onBlur={e=>e.target.style.borderColor='var(--border)'} />
        <button onClick={connect} style={{ background:'var(--cyan)', border:'none', color:'#000', padding:'13px', fontWeight:700, letterSpacing:'0.12em', fontSize:'0.88rem' }}>CONNECT</button>
      </div>
      <div style={{ fontSize:'0.68rem', color:'var(--muted)', letterSpacing:'0.05em' }}>All data encrypted in transit · PII tokenized before AI processing</div>
    </div>
  );
}
