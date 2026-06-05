const LABELS = { UPI_FRAUD:'UPI Fraud', CARD_FRAUD:'Card Fraud', AML:'AML', ACCOUNT_TAKEOVER:'Account Takeover', SYNTHETIC_IDENTITY:'Synthetic ID' };
export default function AlertTypeBadge({ type }) {
  return <span style={{ background:'var(--surface2)', border:'1px solid var(--border)', color:'var(--muted)', padding:'2px 10px', fontSize:'0.7rem', fontWeight:600, letterSpacing:'0.08em', textTransform:'uppercase', whiteSpace:'nowrap' }}>{LABELS[type] || type}</span>;
}
