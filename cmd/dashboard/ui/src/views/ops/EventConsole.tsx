import { useEffect, useRef, useState } from 'react';
import { postJSON } from '../../lib/api';
import type { AdminCtrlReq, DerBase, HubStatus } from './types';
import { evalLimit, formatDelta, serverNowS } from './util';

// Grid event console (brief §4.5): fire a utility constraint at the real bench,
// then watch it land — issued → adopted (hub mRID match) → compliant (meter
// inside limit+150 W for 3 polls) → released — with measured Δt at each hop and
// a verdict chip on settle. All controls target program 0 (Service Point,
// primacy 1), matching the legacy demo. Small controls are safe; Clear reverts.

type EventKind = 'export' | 'import' | 'gen' | 'load' | 'fixed' | 'cease';
const PROGRAM = 0;
const HOLD_N = 3; // consecutive compliant polls (legacy condMet semantics)
const ADOPT_TIMEOUT_MS = 20000;

interface Preset {
  id: EventKind;
  name: string;
  build: (w: number) => Partial<AdminCtrlReq>;
  base: (w: number) => DerBase;
  defaultW: number;
}

const PRESETS: Preset[] = [
  { id: 'export', name: 'Export cap', defaultW: 1000, build: (w) => ({ exp_lim_W: w }), base: (w) => ({ exp_lim_W: w }) },
  { id: 'import', name: 'Import cap', defaultW: 500, build: (w) => ({ imp_lim_W: w }), base: (w) => ({ imp_lim_W: w }) },
  { id: 'gen', name: 'Gen limit', defaultW: 2000, build: (w) => ({ gen_lim_W: w }), base: (w) => ({ gen_lim_W: w }) },
  { id: 'cease', name: 'Cease energize', defaultW: 0, build: () => ({ energize: false }), base: () => ({ energize: false }) },
];

const DURATIONS = [60, 120, 300];

interface TrackedEvent {
  id: number;
  label: string;
  kind: EventKind;
  base: DerBase;
  mrid?: string;
  t0: number;
  adoptedAt?: number;
  compliantAt?: number;
  releasedAt?: number;
  validUntil?: number;
  holdCount: number;
  settled: boolean;
  verdict?: 'pass' | 'released' | 'expired' | 'adopted' | 'never-adopted';
  error?: string;
}

const KIND_LABEL: Record<EventKind, string> = {
  export: 'Export cap', import: 'Import cap', gen: 'Gen limit', load: 'Load limit', fixed: 'Fixed W', cease: 'Cease energize',
};

function verdictChip(v?: TrackedEvent['verdict']) {
  if (v === 'pass') return <span className="ops-chip ops-chip-pass">✓ Complied</span>;
  if (v === 'adopted') return <span className="ops-chip ops-chip-pass">✓ Adopted</span>;
  if (v === 'released') return <span className="ops-chip ops-chip-neutral">Released — no hold</span>;
  if (v === 'expired') return <span className="ops-chip ops-chip-warn">⚠ Expired before hold</span>;
  if (v === 'never-adopted') return <span className="ops-chip ops-chip-fail">✕ Never adopted</span>;
  return null;
}

export function EventConsole({ status }: { status?: HubStatus }) {
  const [events, setEvents] = useState<TrackedEvent[]>([]);
  const [durById, setDurById] = useState<Record<string, number>>({});
  const [note, setNote] = useState<string>('');
  const [custom, setCustom] = useState<{ kind: EventKind; w: number; dur: number }>({ kind: 'export', w: 1000, dur: 120 });
  const idRef = useRef(0);

  // Lifecycle tracker — driven by the parent's 1 s status poll.
  useEffect(() => {
    if (!status) return;
    setEvents((prev) => {
      if (!prev.some((e) => !e.settled)) return prev;
      let changed = false;
      const nowMs = Date.now();
      const csip = status.csip_control;
      const snow = serverNowS(status);
      const next = prev.map((ev) => {
        if (ev.settled) return ev;
        let e = ev;
        const patch = (p: Partial<TrackedEvent>) => { e = { ...e, ...p }; changed = true; };

        // never adopted → give up after a timeout
        if (!e.adoptedAt && nowMs - e.t0 > ADOPT_TIMEOUT_MS) {
          patch({ settled: true, verdict: 'never-adopted', releasedAt: nowMs });
          return e;
        }
        // adoption: hub reports our mRID
        if (!e.adoptedAt && e.mrid && csip?.mrid === e.mrid) {
          patch({ adoptedAt: nowMs, validUntil: csip.valid_until, ...(e.kind === 'cease' ? { compliantAt: nowMs } : {}) });
        }
        // compliance: meter inside limit+tol for HOLD_N consecutive polls
        if (e.adoptedAt && !e.compliantAt && e.kind !== 'cease') {
          const le = evalLimit(e.base, status.power);
          if (le) {
            const hc = le.within ? e.holdCount + 1 : 0;
            if (hc >= HOLD_N) patch({ compliantAt: nowMs, holdCount: hc });
            else patch({ holdCount: hc });
          }
        }
        // release: hub moved off our control, or the window expired
        if (e.adoptedAt && csip && csip.mrid !== e.mrid) {
          patch({ releasedAt: nowMs, settled: true, verdict: e.kind === 'cease' ? 'adopted' : e.compliantAt ? 'pass' : 'released' });
        } else if (e.adoptedAt && !e.settled && e.validUntil && snow >= e.validUntil) {
          patch({ releasedAt: nowMs, settled: true, verdict: e.kind === 'cease' ? 'adopted' : e.compliantAt ? 'pass' : 'expired' });
        }
        return e;
      });
      return changed ? next : prev;
    });
  }, [status]);

  async function fire(kind: EventKind, watts: number, durationS: number) {
    const preset = PRESETS.find((p) => p.id === kind);
    const bodyExtra = preset ? preset.build(watts) : buildCustom(kind, watts);
    const base = preset ? preset.base(watts) : buildCustom(kind, watts);
    const label = kind === 'cease' ? 'Cease energize' : `${KIND_LABEL[kind]} ${watts} W`;
    const id = idRef.current++;
    const t0 = Date.now();
    setEvents((prev) => [{ id, label, kind, base, t0, holdCount: 0, settled: false }, ...prev].slice(0, 12));
    setNote('');
    try {
      const req: AdminCtrlReq = { program: PROGRAM, activate: true, duration_s: durationS, description: `Ops V2 · ${label}`, ...bodyExtra };
      const resp = await postJSON<{ mrid: string }>('/api/gridsim/admin/control', req);
      setEvents((prev) => prev.map((e) => (e.id === id ? { ...e, mrid: resp.mrid } : e)));
    } catch (err) {
      const msg = err instanceof Error ? err.message : String(err);
      setEvents((prev) => prev.map((e) => (e.id === id ? { ...e, settled: true, verdict: 'never-adopted', error: msg, releasedAt: Date.now() } : e)));
      setNote(`Failed to issue control: ${msg}`);
    }
  }

  async function clearControls() {
    setNote('');
    try {
      const resp = await fetch('/api/gridsim/admin/control', {
        method: 'DELETE',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ program: PROGRAM }),
      });
      if (!resp.ok && resp.status !== 204) throw new Error(`HTTP ${resp.status}`);
      const nowMs = Date.now();
      setEvents((prev) => prev.map((e) => (e.settled ? e : { ...e, settled: true, releasedAt: nowMs, verdict: e.kind === 'cease' ? 'adopted' : e.compliantAt ? 'pass' : 'released' })));
      setNote(`Cleared controls on program ${PROGRAM}.`);
    } catch (err) {
      setNote(`Clear failed: ${err instanceof Error ? err.message : String(err)}`);
    }
  }

  const shown = events.slice(0, 5);

  return (
    <div className="ops-card">
      <div className="ops-card-head">
        <h2 className="card-title">Grid Event Console</h2>
        <button className="ops-btn ops-btn-ghost" onClick={clearControls}>Clear controls</button>
      </div>

      <div className="ops-console-top">
        <div className="ops-presets">
          {PRESETS.map((p) => {
            const dur = durById[p.id] ?? 120;
            const w = p.defaultW;
            return (
              <div className="ops-preset" key={p.id}>
                <span className="ops-preset-name">{p.name}{p.id !== 'cease' ? ` ${w >= 1000 ? w / 1000 + ' kW' : w + ' W'}` : ''}</span>
                <div className="ops-preset-row">
                  <select className="ops-select" value={dur} onChange={(e) => setDurById((m) => ({ ...m, [p.id]: Number(e.target.value) }))}>
                    {DURATIONS.map((d) => <option key={d} value={d}>{d}s</option>)}
                  </select>
                  <button className="ops-btn" onClick={() => fire(p.id, w, dur)}>⚡ Fire</button>
                </div>
              </div>
            );
          })}
        </div>

        <div className="ops-custom">
          <div className="ops-field">
            <label>Type</label>
            <select className="ops-select" value={custom.kind} onChange={(e) => setCustom((c) => ({ ...c, kind: e.target.value as EventKind }))}>
              <option value="export">Export cap</option>
              <option value="import">Import cap</option>
              <option value="gen">Gen limit</option>
              <option value="load">Load limit</option>
              <option value="fixed">Fixed W</option>
              <option value="cease">Cease energize</option>
            </select>
          </div>
          <div className="ops-field">
            <label>Watts</label>
            <input className="ops-input" type="number" value={custom.w} disabled={custom.kind === 'cease'} onChange={(e) => setCustom((c) => ({ ...c, w: Number(e.target.value) }))} />
          </div>
          <div className="ops-field">
            <label>Duration</label>
            <select className="ops-select" value={custom.dur} onChange={(e) => setCustom((c) => ({ ...c, dur: Number(e.target.value) }))}>
              {DURATIONS.map((d) => <option key={d} value={d}>{d}s</option>)}
            </select>
          </div>
          <button className="ops-btn" onClick={() => fire(custom.kind, custom.w, custom.dur)}>⚡ Fire custom</button>
        </div>
      </div>

      {note && <div className="ops-console-note">{note}</div>}

      {shown.length === 0 ? (
        <p className="ops-empty">No events fired yet. Pick a preset and press Fire to send a real DERControl to the bench.</p>
      ) : (
        <div className="ops-events">
          {shown.map((e) => <EventRow key={e.id} e={e} /> )}
        </div>
      )}
    </div>
  );
}

function buildCustom(kind: EventKind, w: number): DerBase {
  switch (kind) {
    case 'export': return { exp_lim_W: w };
    case 'import': return { imp_lim_W: w };
    case 'gen': return { gen_lim_W: w };
    case 'load': return { load_lim_W: w };
    case 'fixed': return { fixed_W: w };
    case 'cease': return { energize: false };
  }
}

function EventRow({ e }: { e: TrackedEvent }) {
  const dt = (t?: number) => (t ? formatDelta((t - e.t0) / 1000) : '');
  const steps = [
    { label: 'Issued', on: true, dt: '' },
    { label: 'Adopted', on: !!e.adoptedAt, dt: dt(e.adoptedAt) },
    { label: e.kind === 'cease' ? 'Confirmed' : 'Compliant', on: !!e.compliantAt, dt: dt(e.compliantAt) },
    { label: 'Released', on: !!e.releasedAt, dt: dt(e.releasedAt) },
  ];
  return (
    <div className="ops-event">
      <div className="ops-event-head">
        <span className="ops-event-title">{e.label}</span>
        {e.settled ? verdictChip(e.verdict) : <span className="ops-chip ops-chip-neutral">tracking…</span>}
      </div>
      <div className="ops-timeline">
        {steps.map((s, i) => (
          <div className="ops-tl-step" key={s.label}>
            <div className="ops-tl-dotrow">
              <span className={`ops-tl-dot${s.on ? (s.label === 'Released' && (e.verdict === 'expired' || e.verdict === 'never-adopted') ? ' warn' : ' on') : ''}`} />
              {i < steps.length - 1 && <span className={`ops-tl-line${steps[i + 1].on ? ' on' : ''}`} />}
            </div>
            <span className="ops-tl-label">{s.label}</span>
            <span className="ops-tl-dt">{s.dt || (s.on ? '' : '—')}</span>
          </div>
        ))}
      </div>
      {e.error && <div className="ops-status-line">{e.error}</div>}
    </div>
  );
}
