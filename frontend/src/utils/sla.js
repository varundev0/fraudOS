/**
 * SLA computation — mirrors the Python logic in backend/main.py.
 * Used to enrich demo/mock cases that don't come from the API.
 */

export const SLA_HOURS = { CRITICAL: 4, HIGH: 24, MEDIUM: 72, LOW: 168 };

export const SLA_LABELS = {
  OVERDUE:  { label: 'OVERDUE',  color: 'var(--risk-block)' },
  DUE_SOON: { label: 'DUE SOON', color: '#f59e0b' },
  ON_TRACK: { label: 'ON TRACK', color: 'var(--risk-clear)' },
  RESOLVED: { label: 'RESOLVED', color: 'var(--muted)' },
  UNKNOWN:  { label: 'UNKNOWN',  color: 'var(--muted)' },
};

/**
 * Compute sla_status, sla_deadline, sla_hours_remaining for a case object.
 * If the case already has sla_status from the API, return as-is.
 */
export function computeSLA(c) {
  // API already enriched this case
  if (c.sla_status && c.sla_status !== 'UNKNOWN') return c;

  const totalHours = SLA_HOURS[c.risk_level] || 168;
  const ts = c.received_at || c.created_at;
  if (!ts) return { ...c, sla_status: 'UNKNOWN', sla_deadline: null, sla_hours_remaining: null };

  const deadline = new Date(new Date(ts).getTime() + totalHours * 3_600_000);
  const now = Date.now();

  if (c.decision) {
    return { ...c, sla_status: 'RESOLVED', sla_deadline: deadline.toISOString(), sla_hours_remaining: null };
  }

  const hoursRemaining = (deadline.getTime() - now) / 3_600_000;
  let sla_status;
  if (hoursRemaining < 0) sla_status = 'OVERDUE';
  else if (hoursRemaining < totalHours * 0.25) sla_status = 'DUE_SOON';
  else sla_status = 'ON_TRACK';

  return {
    ...c,
    sla_status,
    sla_deadline: deadline.toISOString(),
    sla_hours_remaining: Math.round(hoursRemaining * 10) / 10,
  };
}

/** Human-readable time remaining / overdue label. */
export function slaTimeLabel(hoursRemaining) {
  if (hoursRemaining === null || hoursRemaining === undefined) return null;
  const abs = Math.abs(hoursRemaining);
  const overdue = hoursRemaining < 0;
  let str;
  if (abs < 1) str = `${Math.round(abs * 60)}m`;
  else if (abs < 24) str = `${Math.round(abs)}h`;
  else str = `${Math.round(abs / 24)}d`;
  return overdue ? `${str} overdue` : `${str} left`;
}
