import { useEffect, useState } from 'react';
import { usePoll } from '../../lib/usePoll';
import { getJSON } from '../../lib/api';
import { formatWatts, formatDuration } from '../../lib/format';
import { POWER_COLORS } from '../../lib/colors';
import type { AdminStatus, AdvertisedCurve, CurveMode, HubStatus } from './types';
import type { SolarAdvancedState } from '../bench/types';
import { useEventTracker } from './useEventTracker';
import { EventTimeline, verdictChip } from './EventTimeline';
import { serverNowS } from './util';
import { clearCurve, clearGridControl, fireCurve, fireGridControl } from './scenarioApi';
import {
  armOpenADRCap,
  armOpenADRPrice,
  clearOpenADREvent,
  upsertOpenADRProgram,
  type VtnAdminState,
} from './vtnApi';

// Advanced / Standards console (Phase 3): two investor-demo controls that sit
// beside the Injection Console and drive the two standards reaches the campaign
// added — (A) IEEE 1547 / CSIP DER function CURVES (Volt-VAr et al.) and (B)
// OpenADR 3.x utility EVENTS. Same tile/tracker vocabulary as Phase 2; every
// call rides an existing/specified /api proxy mount, no hub-side changes.

const AMBER = POWER_COLORS.solar;
const TEAL = POWER_COLORS.ev;
const FIXED_VAR_DUR_S = 300;

// ── Part A — DER function curves ─────────────────────────────────────────────

const MODE_MODEL: Record<CurveMode, number> = {
  volt_var: 705,
  volt_watt: 706,
  freq_watt: 711,
  watt_pf: 712,
};
const MODE_LABEL: Record<CurveMode, string> = {
  volt_var: 'Volt-VAr',
  volt_watt: 'Volt-Watt',
  freq_watt: 'Freq-Watt',
  watt_pf: 'Watt-PF',
};
const MODE_AXES: Record<CurveMode, { x: string; y: string }> = {
  volt_var: { x: '%V', y: '%VAr' },
  volt_watt: { x: '%V', y: '%W' },
  freq_watt: { x: 'Hz', y: '%W' },
  watt_pf: { x: '%W', y: '%VAr' },
};
const CURVE_DURATIONS = [120, 300, 600];

interface CurvePreset {
  id: string;
  name: string;
  mode: CurveMode;
  vref?: number;
  points: [number, number][];
}

// 2-3 presets for the headline Volt-VAr mode + one each for the others, so the
// mode selector always has something to fire. Points are (x,y) per MODE_AXES.
const PRESETS: CurvePreset[] = [
  { id: 'vv-std', name: 'Standard (1547 Cat-B)', mode: 'volt_var', vref: 100, points: [[92, 30], [98, 0], [102, 0], [108, -30]] },
  { id: 'vv-agg', name: 'Aggressive', mode: 'volt_var', vref: 100, points: [[94, 44], [99, 0], [101, 0], [106, -44]] },
  { id: 'vw-std', name: 'Curtail above 106%', mode: 'volt_watt', vref: 100, points: [[100, 100], [106, 100], [110, 20]] },
  { id: 'fw-std', name: 'Droop (60 Hz)', mode: 'freq_watt', points: [[60.0, 100], [60.5, 100], [61.2, 0]] },
  { id: 'wpf-std', name: 'Absorb at high output', mode: 'watt_pf', points: [[0, 0], [50, 0], [100, -30]] },
];

interface IssuedCurve {
  mode: CurveMode;
  vref?: number;
  points: [number, number][];
}

function trimNum(n: number): string {
  return Number.isInteger(n) ? String(n) : n.toFixed(n % 1 && Math.abs(n) < 10 ? 1 : 2).replace(/\.?0+$/, '');
}
function fmtPoint([x, y]: [number, number], ax: { x: string; y: string }): string {
  const ys = y > 0 ? `+${trimNum(y)}` : trimNum(y);
  return `${trimNum(x)}${ax.x} → ${ys}${ax.y}`;
}
function modeLabel(m?: CurveMode | string): string {
  if (!m) return '—';
  return MODE_LABEL[m as CurveMode] ?? m;
}
function adminCurve(admin?: AdminStatus): AdvertisedCurve | null {
  for (const p of admin?.programs ?? []) {
    if (p.curve && (p.curve.points?.length || p.curve.mode)) return p.curve;
  }
  return null;
}

export function CurveConsole({ status }: { status?: HubStatus }) {
  const { data: solar } = usePoll<SolarAdvancedState>(() => getJSON<SolarAdvancedState>('/api/solar/state'), 1000);
  const { data: admin } = usePoll<AdminStatus>(() => getJSON<AdminStatus>('/api/gridsim/admin/status'), 2000);

  const [mode, setMode] = useState<CurveMode>('volt_var');
  const [presetId, setPresetId] = useState('vv-std');
  const [dur, setDur] = useState(300);
  const [varPct, setVarPct] = useState(30);
  const [issued, setIssued] = useState<IssuedCurve | null>(null);
  const [note, setNote] = useState('');

  const varCtl = useEventTracker(status, 3);
  const varEv = varCtl.events[0];

  const presetsForMode = PRESETS.filter((p) => p.mode === mode);
  const preset = PRESETS.find((p) => p.id === presetId) ?? presetsForMode[0] ?? PRESETS[0];
  const ax = MODE_AXES[mode];

  function pickMode(m: CurveMode) {
    setMode(m);
    const first = PRESETS.find((p) => p.mode === m);
    if (first) setPresetId(first.id);
  }

  async function activateCurve() {
    setNote('');
    const pts = preset.points.map(([x, y]) => ({ x, y }));
    try {
      await fireCurve(mode, pts, { vref: preset.vref, durationS: dur });
      setIssued({ mode, vref: preset.vref, points: preset.points });
      setNote(`Activated ${MODE_LABEL[mode]} curve — watch the device adopt it.`);
    } catch (err) {
      setIssued({ mode, vref: preset.vref, points: preset.points });
      setNote(`Curve POST failed: ${msg(err)} (gridsim /admin/curve may not be deployed yet).`);
    }
  }

  async function releaseCurve() {
    setNote('');
    await clearCurve();
    setIssued(null);
    setNote('Released the active curve.');
  }

  async function applyFixedVar() {
    const label = `Fixed VAr ${varPct > 0 ? '+' : ''}${varPct}%`;
    const id = varCtl.track({ label, kind: 'fixed', base: { fixed_var_pct: varPct } });
    setNote('');
    try {
      const { mrid } = await fireGridControl({ fixed_var_pct: varPct }, FIXED_VAR_DUR_S, `Advanced · ${label}`);
      varCtl.attachMrid(id, mrid);
    } catch (err) {
      varCtl.settle(id, 'never-adopted', msg(err));
      setNote(`Fixed VAr failed: ${msg(err)}`);
    }
  }

  function clearFixedVar() {
    clearGridControl();
    varCtl.settleAll(() => 'adopted');
  }

  // advertised → adopted → measured
  const activeMode = issued?.mode ?? mode;
  const advertised = adminCurve(admin) ?? issued;
  const adopted = (solar?.curves ?? []).find((c) => c.model === MODE_MODEL[activeMode]);
  const adoptedDone = adopted?.adopt_rslt === 1;
  const m701 = solar?.meas_701;
  const fixedVar = solar?.fixed_var;

  return (
    <div className="ops-card">
      <div className="ops-card-head">
        <div>
          <h2 className="card-title">VAr / Volt-VAr Control</h2>
          <div className="ops-card-sub">activate a DER autonomous function curve — watch the device adopt it</div>
        </div>
        <button className="ops-btn ops-btn-ghost" onClick={releaseCurve}>↺ Release curve</button>
      </div>

      <div className="ops-adv-controls">
        <div className="ops-field">
          <label>Mode</label>
          <select className="ops-select" value={mode} onChange={(e) => pickMode(e.target.value as CurveMode)}>
            {(Object.keys(MODE_LABEL) as CurveMode[]).map((m) => (
              <option key={m} value={m}>{MODE_LABEL[m]} · {MODE_MODEL[m]}</option>
            ))}
          </select>
        </div>
        <div className="ops-field">
          <label>Preset curve</label>
          <select className="ops-select" value={presetId} onChange={(e) => setPresetId(e.target.value)}>
            {presetsForMode.map((p) => <option key={p.id} value={p.id}>{p.name}</option>)}
          </select>
        </div>
        <div className="ops-field">
          <label>Duration</label>
          <select className="ops-select" value={dur} onChange={(e) => setDur(Number(e.target.value))}>
            {CURVE_DURATIONS.map((d) => <option key={d} value={d}>{d}s</option>)}
          </select>
        </div>
        <div className="ops-adv-actions">
          <button className="ops-btn" onClick={activateCurve}>⚡ Activate curve</button>
        </div>
      </div>
      <div className="ops-points">
        {preset.points.map((p, i) => <span key={i}>{fmtPoint(p, ax)}</span>)}
        {preset.vref != null && <span>Vref {preset.vref}%</span>}
      </div>

      {/* fixed VAr / PF — the simpler direct lever, tracked issued → adopted */}
      <div className="ops-adv-fixedvar">
        <div className="ops-slider-row">
          <input
            className="ops-slider"
            style={{ accentColor: AMBER }}
            type="range"
            min={-60}
            max={60}
            step={5}
            value={varPct}
            onChange={(e) => setVarPct(Number(e.target.value))}
            aria-label="Fixed VAr (% of rating)"
          />
          <span className="ops-slider-val" style={{ color: AMBER }}>{varPct > 0 ? '+' : ''}{varPct}%</span>
        </div>
        <div className="ops-slider-ends"><span>absorb −</span><span>fixed VAr</span><span>+ inject</span></div>
        <div className="ops-tile-controls">
          <span className="ops-readout">DERControl · OpModFixedVar</span>
          <div className="ops-adv-actions">
            <button className="ops-btn" onClick={applyFixedVar}>⚡ Apply fixed VAr</button>
            <button className="ops-btn ops-btn-ghost" onClick={clearFixedVar}>Clear</button>
          </div>
        </div>
        {varEv && (
          <div className="ops-tile-track">
            <div className="ops-tile-track-head">
              <span className="ops-tile-track-label">{varEv.label}</span>
              {varEv.settled ? verdictChip(varEv.verdict) : <span className="ops-chip ops-chip-neutral">tracking…</span>}
            </div>
            <EventTimeline e={varEv} />
          </div>
        )}
      </div>

      {/* advertised → adopted → measured */}
      <div className="ops-inspector" style={{ marginTop: 14 }}>
        <div>
          <p className="ops-col-title">Advertised · gridsim</p>
          <p className="ops-col-sub">the curve bound to the DER program</p>
          <div className="ops-col-body">
            {advertised ? (
              <div className="ops-prog">
                <div className="ops-prog-head">
                  <span className="ops-chip ops-chip-mode">{modeLabel(advertised.mode ?? activeMode)}</span>
                  {advertised.vref != null && <span className="ops-badge-primacy">Vref {advertised.vref}%</span>}
                </div>
                <div className="ops-points">
                  {(advertised.points ?? []).map((p, i) => <span key={i}>{fmtPoint(p, MODE_AXES[(advertised.mode as CurveMode) ?? activeMode] ?? ax)}</span>)}
                </div>
              </div>
            ) : (
              <p className="ops-empty">No curve activated yet.</p>
            )}
          </div>
        </div>

        <div>
          <p className="ops-col-title">Adopted · device</p>
          <p className="ops-col-sub">SunSpec 7xx adopt result + live curve</p>
          <div className="ops-col-body">
            {adopted ? (
              <div className={`ops-adopted${adoptedDone ? ' matched' : ''}`}>
                <div className="ops-prog-head">
                  <span className="ops-chip ops-chip-mode">model {adopted.model}</span>
                  {adoptedDone ? (
                    <span className="ops-chip ops-chip-pass" title="AdptCrvRslt = COMPLETED">✓ COMPLETED</span>
                  ) : (
                    <span className="ops-chip ops-chip-neutral">in-progress</span>
                  )}
                </div>
                <div className="ops-points" style={{ marginTop: 6 }}>
                  {adopted.points.map((p, i) => <span key={i}>{fmtPoint(p, MODE_AXES[activeMode])}</span>)}
                </div>
              </div>
            ) : (
              <p className="ops-empty">{solar?.curves ? 'No adopted curve for this mode.' : 'Advanced solar sim not reporting curves.'}</p>
            )}
          </div>
        </div>

        <div>
          <p className="ops-col-title">Measured · 701</p>
          <p className="ops-col-sub">the reactive power the device actually makes</p>
          <div className="ops-col-body">
            {m701 ? (
              <div className="ops-adopted">
                <div className="ops-stat-label">Reactive power</div>
                <div className="ops-meas-big">{Math.round(m701.VAr_var)} var</div>
                <div className="ops-kv" style={{ marginTop: 8 }}>
                  <div><span className="k">PF </span><span className="v">{m701.PF.toFixed(3)}</span></div>
                  <div><span className="k">W </span><span className="v">{formatWatts(m701.W_W)}</span></div>
                  {fixedVar?.ena && <div><span className="k">fixed var </span><span className="v">{trimNum(fixedVar.pct)}%</span></div>}
                </div>
              </div>
            ) : (
              <p className="ops-empty">No 701 measurement.</p>
            )}
          </div>
        </div>
      </div>

      {note && <div className="ops-console-note">{note}</div>}
    </div>
  );
}

// ── Part B — OpenADR utility event ───────────────────────────────────────────

const OADR_DURATIONS: { iso: string; label: string }[] = [
  { iso: 'PT15M', label: '15 min' },
  { iso: 'PT1H', label: '1 hour' },
  { iso: 'PT2H', label: '2 hours' },
];

type ArmedKind = 'PRICE' | 'CAP';
interface ArmedEvent {
  id: string;
  kind: ArmedKind;
  label: string;
}

export function OpenADRConsole({ status }: { status?: HubStatus }) {
  // VTN's own view — fallback readout + reachability probe when the hub has not
  // yet surfaced status.openadr. undefined = loading, null = unreachable.
  const { data: vtnState } = usePoll<VtnAdminState | null>(
    () => getJSON<VtnAdminState>('/api/vtn/admin/state').catch(() => null),
    3000
  );

  const [priceVal, setPriceVal] = useState(0.45);
  const [capW, setCapW] = useState(2000);
  const [durISO, setDurISO] = useState('PT1H');
  const [armed, setArmed] = useState<ArmedEvent[]>([]);
  const [note, setNote] = useState('');

  // 1 Hz repaint so "last poll … ago" advances on an idle bench.
  const [, setTick] = useState(0);
  useEffect(() => {
    const t = setInterval(() => setTick((n) => n + 1), 1000);
    return () => clearInterval(t);
  }, []);

  async function armPrice() {
    const id = `lexa-price-${Date.now()}`;
    setNote('');
    try {
      await upsertOpenADRProgram('PRICE');
      await armOpenADRPrice(id, priceVal, durISO);
      const ev: ArmedEvent = { id, kind: 'PRICE', label: `$${priceVal.toFixed(2)}/kWh` };
      setArmed((a) => [ev, ...a].slice(0, 6));
      setNote('Armed PRICE event — the VEN adopts it into the plan’s price_forecast (chart below).');
    } catch (err) {
      setNote(`Arm PRICE failed: ${msg(err)} (VTN backend may not be deployed yet).`);
    }
  }

  async function armCap() {
    const id = `lexa-cap-${Date.now()}`;
    setNote('');
    try {
      await upsertOpenADRProgram('IMPORT_CAPACITY_LIMIT');
      await armOpenADRCap(id, capW, durISO);
      const ev: ArmedEvent = { id, kind: 'CAP', label: `Import ≤ ${formatWatts(capW)}` };
      setArmed((a) => [ev, ...a].slice(0, 6));
      setNote('Armed IMPORT cap — adopted & enforced (D9), never a CannotComply.');
    } catch (err) {
      setNote(`Arm IMPORT cap failed: ${msg(err)} (VTN backend may not be deployed yet).`);
    }
  }

  async function clearOne(id: string) {
    await clearOpenADREvent(id);
    setArmed((a) => a.filter((e) => e.id !== id));
  }

  // Health — prefer the hub's VEN report, fall back to the VTN's own state.
  const oa = status?.openadr;
  const usingHub = !!oa;
  const vtnReachable = usingHub ? !!oa?.vtn_ok : vtnState != null;
  const tokenOk = oa?.token_ok;
  const activeEvents = oa?.active_events ?? vtnState?.events?.length ?? armed.length;
  const programs = oa?.programs ?? vtnState?.programs?.length;
  const lastPollTs = oa?.last_poll_ts;
  const lastErr = oa?.last_err;
  const pollAge = lastPollTs != null ? Math.max(0, serverNowS(status) - lastPollTs) : null;

  return (
    <div className="ops-card">
      <div className="ops-card-head">
        <div>
          <h2 className="card-title">OpenADR Utility Event</h2>
          <div className="ops-card-sub">arm a VTN event — watch the VEN adopt it onto the hub</div>
        </div>
        <span className="ops-head-meta">{usingHub ? 'via hub /status' : vtnState != null ? 'via VTN /admin/state' : 'VTN backend pending'}</span>
      </div>

      {/* VEN health chips */}
      <div className="ops-health">
        <span className={`ops-chip ${vtnReachable ? 'ops-chip-pass' : 'ops-chip-warn'}`}>
          {vtnReachable ? '✓ VTN reachable' : '⚠ VTN unreachable'}
        </span>
        {tokenOk != null && (
          <span className={`ops-chip ${tokenOk ? 'ops-chip-pass' : 'ops-chip-warn'}`}>{tokenOk ? '✓ token ok' : '⚠ token'}</span>
        )}
        <span className="ops-chip ops-chip-info">{activeEvents} active event{activeEvents === 1 ? '' : 's'}</span>
        {programs != null && <span className="ops-chip ops-chip-neutral">{programs} program{programs === 1 ? '' : 's'}</span>}
        {pollAge != null && <span className="ops-chip ops-chip-neutral">polled {formatDuration(pollAge)} ago</span>}
        {lastErr && <span className="ops-chip ops-chip-fail" title={lastErr}>✕ {lastErr.slice(0, 40)}</span>}
      </div>

      <div className="ops-adv-controls">
        <div className="ops-field">
          <label>Price ($/kWh)</label>
          <input className="ops-input" type="number" step={0.05} min={0} value={priceVal} onChange={(e) => setPriceVal(Number(e.target.value))} />
        </div>
        <div className="ops-adv-actions">
          <button className="ops-btn" style={{ borderColor: TEAL, background: TEAL }} onClick={armPrice}>⚡ Arm PRICE</button>
        </div>
        <div className="ops-field">
          <label>Import cap (W)</label>
          <input className="ops-input" type="number" step={250} min={0} value={capW} onChange={(e) => setCapW(Number(e.target.value))} />
        </div>
        <div className="ops-adv-actions">
          <button className="ops-btn" style={{ borderColor: TEAL, background: TEAL }} onClick={armCap}>⚡ Arm IMPORT cap</button>
        </div>
        <div className="ops-field">
          <label>Duration</label>
          <select className="ops-select" value={durISO} onChange={(e) => setDurISO(e.target.value)}>
            {OADR_DURATIONS.map((d) => <option key={d.iso} value={d.iso}>{d.label}</option>)}
          </select>
        </div>
      </div>

      {armed.length > 0 && (
        <div className="ops-armed">
          {armed.map((e) => (
            <span className="ops-banner-pill" key={e.id}>
              <span className="ops-banner-dot" style={{ background: TEAL }} />
              <span className="ops-banner-txt">
                <strong>{e.kind === 'PRICE' ? 'PRICE' : 'IMPORT cap'}</strong> · {e.label}
              </span>
              <button className="ops-banner-clear" onClick={() => clearOne(e.id)} title="Clear event" aria-label="Clear event">✕</button>
            </span>
          ))}
        </div>
      )}

      <p className="ops-tile-hint">
        An armed <strong>PRICE</strong> flows into the Plan chart’s <code>price_forecast</code> below; an armed{' '}
        <strong>cap</strong> bends the meter in Power Flow. An OpenADR-adopted cap is{' '}
        <span className="ops-chip ops-chip-info">adopted &amp; enforced (D9)</span> — never a CannotComply/breach.
      </p>

      {note && <div className="ops-console-note">{note}</div>}
    </div>
  );
}

// ── wrapper ──────────────────────────────────────────────────────────────────

export function AdvancedConsole({ status }: { status?: HubStatus }) {
  return (
    <>
      <CurveConsole status={status} />
      <OpenADRConsole status={status} />
    </>
  );
}

function msg(err: unknown): string {
  return err instanceof Error ? err.message : String(err);
}
