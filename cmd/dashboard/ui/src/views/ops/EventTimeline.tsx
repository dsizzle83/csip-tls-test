import type { TrackedEvent, Verdict } from './useEventTracker';
import { formatDelta } from './util';

// Presentational bits for a fired-control lifecycle, shared by the Grid Event
// Console and the Injection Console (task: reuse ops-timeline / ops-tl-* classes).

export function verdictChip(v?: Verdict) {
  if (v === 'pass') return <span className="ops-chip ops-chip-pass">✓ Complied</span>;
  if (v === 'adopted') return <span className="ops-chip ops-chip-pass">✓ Adopted</span>;
  if (v === 'released') return <span className="ops-chip ops-chip-neutral">Released — no hold</span>;
  if (v === 'expired') return <span className="ops-chip ops-chip-warn">⚠ Expired before hold</span>;
  if (v === 'never-adopted') return <span className="ops-chip ops-chip-fail">✕ Never adopted</span>;
  return null;
}

/** The four-hop issued → adopted → compliant → released strip with per-hop Δt. */
export function EventTimeline({ e }: { e: TrackedEvent }) {
  const dt = (t?: number) => (t ? formatDelta((t - e.t0) / 1000) : '');
  const steps = [
    { label: 'Issued', on: true, dt: '' },
    { label: 'Adopted', on: !!e.adoptedAt, dt: dt(e.adoptedAt) },
    { label: e.kind === 'cease' ? 'Confirmed' : 'Compliant', on: !!e.compliantAt, dt: dt(e.compliantAt) },
    { label: 'Released', on: !!e.releasedAt, dt: dt(e.releasedAt) },
  ];
  return (
    <div className="ops-timeline">
      {steps.map((s, i) => (
        <div className="ops-tl-step" key={s.label}>
          <div className="ops-tl-dotrow">
            <span
              className={`ops-tl-dot${
                s.on ? (s.label === 'Released' && (e.verdict === 'expired' || e.verdict === 'never-adopted') ? ' warn' : ' on') : ''
              }`}
            />
            {i < steps.length - 1 && <span className={`ops-tl-line${steps[i + 1].on ? ' on' : ''}`} />}
          </div>
          <span className="ops-tl-label">{s.label}</span>
          <span className="ops-tl-dt">{s.dt || (s.on ? '' : '—')}</span>
        </div>
      ))}
    </div>
  );
}
