import { useState } from 'react';
import { postJSON } from '../../lib/api';
import type { AdminCtrlReq, DerBase, HubStatus } from './types';
import { KIND_LABEL, useEventTracker, type EventKind, type TrackedEvent } from './useEventTracker';
import { EventTimeline, verdictChip } from './EventTimeline';

// Grid event console (brief §4.5): fire a utility constraint at the real bench,
// then watch it land via useEventTracker — issued → adopted (hub mRID match) →
// compliant (meter inside limit+150 W for 3 polls) → released — with measured Δt
// at each hop and a verdict chip on settle. All controls target program 0
// (Service Point, primacy 1), matching the legacy demo. Small controls are safe;
// Clear reverts.

const PROGRAM = 0;

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

export function EventConsole({ status }: { status?: HubStatus }) {
  const { events, track, attachMrid, settle, settleAll } = useEventTracker(status);
  const [durById, setDurById] = useState<Record<string, number>>({});
  const [note, setNote] = useState<string>('');
  const [custom, setCustom] = useState<{ kind: EventKind; w: number; dur: number }>({ kind: 'export', w: 1000, dur: 120 });

  async function fire(kind: EventKind, watts: number, durationS: number) {
    const preset = PRESETS.find((p) => p.id === kind);
    const bodyExtra = preset ? preset.build(watts) : buildCustom(kind, watts);
    const base = preset ? preset.base(watts) : buildCustom(kind, watts);
    const label = kind === 'cease' ? 'Cease energize' : `${KIND_LABEL[kind]} ${watts} W`;
    const id = track({ label, kind, base });
    setNote('');
    try {
      const req: AdminCtrlReq = { program: PROGRAM, activate: true, duration_s: durationS, description: `Ops V2 · ${label}`, ...bodyExtra };
      const resp = await postJSON<{ mrid: string }>('/api/gridsim/admin/control', req);
      attachMrid(id, resp.mrid);
    } catch (err) {
      const msg = err instanceof Error ? err.message : String(err);
      settle(id, 'never-adopted', msg);
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
      settleAll((e) => (e.kind === 'cease' ? 'adopted' : e.compliantAt ? 'pass' : 'released'));
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
  return (
    <div className="ops-event">
      <div className="ops-event-head">
        <span className="ops-event-title">{e.label}</span>
        {e.settled ? verdictChip(e.verdict) : <span className="ops-chip ops-chip-neutral">tracking…</span>}
      </div>
      <EventTimeline e={e} />
      {e.error && <div className="ops-status-line">{e.error}</div>}
    </div>
  );
}
