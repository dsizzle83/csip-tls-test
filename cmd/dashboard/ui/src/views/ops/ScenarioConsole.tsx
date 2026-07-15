import { useEffect, useRef, useState } from 'react';
import type { ReactNode } from 'react';
import { usePoll } from '../../lib/usePoll';
import { getJSON } from '../../lib/api';
import { formatWatts } from '../../lib/format';
import { POWER_COLORS } from '../../lib/colors';
import type { HubStatus } from './types';
import type { SolarState } from '../bench/types';
import { useEventTracker, type TrackedEvent } from './useEventTracker';
import { EventTimeline, verdictChip } from './EventTimeline';
import { evalLimit, formatCountdown, serverNowS } from './util';
import { clearGridControl, curtailInverter, fireGridControl, resumeHomeLoad, setCloud, spikeHomeLoad } from './scenarioApi';

// Injection Console (pitch surface, brief §3/§5): a presenter drives the live
// bench — solar curtailment, a demand-response event, cloudy weather — and the
// Ops panels below (Plan, PowerFlow, Protocol Inspector) show the hub reacting.
// No hub-side changes: everything rides the EXISTING gridsim /admin/control and
// sim /inject endpoints. Three tiles + an active-injections banner + Restore.

const DURATIONS = [60, 120, 300]; // grid-control window chips (s)
const SURGE_W = 6000; // "+ home surge" pinned house load (W)
const RESTORE_LOAD_MEAN_W = 2000; // baseline mean the meter resumes to (W)
const RESTORE_INVERTER_PCT = 100; // release any direct inverter curtailment
const CLOUD_APPLY_MS = 180; // debounce for the live cloud slider

const AMBER = POWER_COLORS.solar; // --c-amber (solar / weather)
const BLUE = POWER_COLORS.grid; // --c-blue (grid / demand)

interface AlertsResp {
  alerts: { subject: string; status: number; vocab: string; received_at: number }[];
  server_time: number;
}

export function ScenarioConsole({ status }: { status?: HubStatus }) {
  // Live solar state — drives the Cloudy Weather readout + banner. Its own poll
  // (the shared `status` carries no cloud/irradiance field).
  const { data: solar } = usePoll(() => getJSON<SolarState>('/api/solar/state'), 1000);
  // CannotComply proof: gridsim records the hub's Responses; a subject match on
  // the demand-response mRID lights the breach chip live.
  const { data: alertsData } = usePoll(() => getJSON<AlertsResp>('/api/gridsim/admin/alerts'), 2000);

  // Two independent CSIP lifecycle trackers, one per grid-control tile.
  const solarCtl = useEventTracker(status, 4);
  const drCtl = useEventTracker(status, 4);

  // Tile inputs.
  const [solarKw, setSolarKw] = useState(2);
  const [solarDur, setSolarDur] = useState(120);
  const [drKw, setDrKw] = useState(2);
  const [drDur, setDrDur] = useState(120);
  const [surge, setSurge] = useState(false);
  const [cloudPct, setCloudPct] = useState(0); // last value WE applied

  // Fire-time window estimates (epoch ms) for the banner countdown before the
  // hub reports valid_until; null once inactive.
  const [solarExpiry, setSolarExpiry] = useState<number | null>(null);
  const [drExpiry, setDrExpiry] = useState<number | null>(null);
  const [surgeUntil, setSurgeUntil] = useState<number | null>(null);
  const [note, setNote] = useState('');

  // Timers we own — surge auto-revert + cloud-slider debounce; cancel on unmount.
  const surgeTimer = useRef<ReturnType<typeof setTimeout> | null>(null);
  const cloudTimer = useRef<ReturnType<typeof setTimeout> | null>(null);
  useEffect(
    () => () => {
      if (surgeTimer.current) clearTimeout(surgeTimer.current);
      if (cloudTimer.current) clearTimeout(cloudTimer.current);
    },
    []
  );

  const solarEv = solarCtl.events[0];
  const drEv = drCtl.events[0];
  const solarActive = !!solarEv && !solarEv.settled;
  const drActive = !!drEv && !drEv.settled;
  const hasActive = solarActive || drActive || surgeUntil != null || cloudPct > 0;

  // 1 Hz repaint so the banner countdowns advance even when `status` is
  // byte-identical (idle bench keeps object identity stable).
  const [, setTick] = useState(0);
  useEffect(() => {
    if (!hasActive) return;
    const t = setInterval(() => setTick((n) => n + 1), 1000);
    return () => clearInterval(t);
  }, [hasActive]);

  async function fireSolar() {
    const base = { gen_lim_W: Math.round(solarKw * 1000) };
    const label = `Generation ≤ ${kwLabel(solarKw)}`;
    const id = solarCtl.track({ label, kind: 'gen', base });
    setSolarExpiry(Date.now() + solarDur * 1000);
    setNote('');
    try {
      const { mrid } = await fireGridControl(base, solarDur, `Injection Console · ${label}`);
      solarCtl.attachMrid(id, mrid);
    } catch (err) {
      const msg = err instanceof Error ? err.message : String(err);
      solarCtl.settle(id, 'never-adopted', msg);
      setSolarExpiry(null);
      setNote(`Solar curtailment failed: ${msg}`);
    }
  }

  async function fireDR() {
    const base = { imp_lim_W: Math.round(drKw * 1000) };
    const label = `Import ≤ ${kwLabel(drKw)}`;
    const id = drCtl.track({ label, kind: 'import', base });
    setDrExpiry(Date.now() + drDur * 1000);
    setNote('');
    if (surge) {
      spikeHomeLoad(SURGE_W);
      setSurgeUntil(Date.now() + drDur * 1000);
      if (surgeTimer.current) clearTimeout(surgeTimer.current);
      surgeTimer.current = setTimeout(() => {
        resumeHomeLoad(RESTORE_LOAD_MEAN_W);
        setSurgeUntil(null);
        surgeTimer.current = null;
      }, drDur * 1000);
    }
    try {
      const { mrid } = await fireGridControl(base, drDur, `Injection Console · ${label}`);
      drCtl.attachMrid(id, mrid);
    } catch (err) {
      const msg = err instanceof Error ? err.message : String(err);
      drCtl.settle(id, 'never-adopted', msg);
      setDrExpiry(null);
      setNote(`Demand response failed: ${msg}`);
    }
  }

  function applyCloud(pct: number) {
    setCloudPct(pct);
    if (cloudTimer.current) clearTimeout(cloudTimer.current);
    cloudTimer.current = setTimeout(() => {
      setCloud(pct);
      cloudTimer.current = null;
    }, CLOUD_APPLY_MS);
  }

  function clearCloud() {
    if (cloudTimer.current) {
      clearTimeout(cloudTimer.current);
      cloudTimer.current = null;
    }
    setCloudPct(0);
    setCloud(0);
  }

  // program-0 DELETE is scoped to the whole program, so one Clear drops both
  // grid controls — honest, and the common case fires one at a time anyway.
  function clearGridCtls() {
    clearGridControl();
    solarCtl.settleAll((e) => (e.compliantAt ? 'pass' : 'released'));
    drCtl.settleAll((e) => (e.compliantAt ? 'pass' : 'released'));
    setSolarExpiry(null);
    setDrExpiry(null);
  }

  function clearSurge() {
    if (surgeTimer.current) {
      clearTimeout(surgeTimer.current);
      surgeTimer.current = null;
    }
    resumeHomeLoad(RESTORE_LOAD_MEAN_W);
    setSurgeUntil(null);
  }

  async function restoreBench() {
    if (surgeTimer.current) {
      clearTimeout(surgeTimer.current);
      surgeTimer.current = null;
    }
    if (cloudTimer.current) {
      clearTimeout(cloudTimer.current);
      cloudTimer.current = null;
    }
    setNote('Restoring bench…');
    await Promise.allSettled([clearGridControl(), setCloud(0), resumeHomeLoad(RESTORE_LOAD_MEAN_W), curtailInverter(RESTORE_INVERTER_PCT)]);
    solarCtl.settleAll((e) => (e.compliantAt ? 'pass' : 'released'));
    drCtl.settleAll((e) => (e.compliantAt ? 'pass' : 'released'));
    setSolarExpiry(null);
    setDrExpiry(null);
    setSurgeUntil(null);
    setCloudPct(0);
    setSurge(false);
    setNote('Bench restored to baseline.');
  }

  // ── active-injections banner ──────────────────────────────────────────────
  const nowMs = Date.now();
  const liveCloud = solar?.measurements?.Cloud_pct;
  const shownCloud = liveCloud ?? cloudPct;
  const drMrid = drEv?.mrid;
  const drCannotComply = !!drMrid && (alertsData?.alerts ?? []).some((a) => a.subject === drMrid);

  interface Pill {
    key: string;
    color: string;
    label: string;
    detail?: string;
    onClear: () => void;
  }
  const pills: Pill[] = [];
  if (cloudPct > 0 || (liveCloud ?? 0) > 0) {
    pills.push({ key: 'cloud', color: AMBER, label: 'Cloudy Weather', detail: `${Math.round(shownCloud)}% overcast`, onClear: clearCloud });
  }
  if (solarActive && solarEv) {
    pills.push({ key: 'solar', color: AMBER, label: 'Solar Curtailment', detail: gridPillDetail(solarEv, solarExpiry, status), onClear: clearGridCtls });
  }
  if (drActive && drEv) {
    pills.push({ key: 'dr', color: BLUE, label: 'Demand Response', detail: gridPillDetail(drEv, drExpiry, status), onClear: clearGridCtls });
  }
  if (surgeUntil != null && nowMs < surgeUntil) {
    pills.push({ key: 'surge', color: BLUE, label: 'Home Surge', detail: `+${kwLabel(SURGE_W / 1000)} load · ${formatCountdown((surgeUntil - nowMs) / 1000)} left`, onClear: clearSurge });
  }

  return (
    <div className="ops-card">
      <div className="ops-card-head">
        <div>
          <h2 className="card-title">Injection Console</h2>
          <div className="ops-card-sub">drive the bench — watch the hub react</div>
        </div>
        <button className="ops-btn ops-btn-ghost" onClick={restoreBench}>↺ Restore bench</button>
      </div>

      {pills.length > 0 && (
        <div className="ops-banner">
          <span className="ops-banner-lead">Now injecting</span>
          {pills.map((p) => (
            <span className="ops-banner-pill" key={p.key}>
              <span className="ops-banner-dot" style={{ background: p.color }} />
              <span className="ops-banner-txt">
                <strong>{p.label}</strong>
                {p.detail ? ` · ${p.detail}` : ''}
              </span>
              <button className="ops-banner-clear" onClick={p.onClear} title={`Clear ${p.label}`} aria-label={`Clear ${p.label}`}>✕</button>
            </span>
          ))}
        </div>
      )}

      <div className="ops-scenario-grid">
        {/* ── Solar Curtailment (CSIP gen cap) ── */}
        <ScenarioTile icon="☀︎↓" title="Solar Curtailment" sub="cap generation — watch the hub enforce it" accent={AMBER}>
          <div className="ops-slider-row">
            <input className="ops-slider" style={{ accentColor: AMBER }} type="range" min={0.5} max={5} step={0.5} value={solarKw} onChange={(e) => setSolarKw(Number(e.target.value))} aria-label="Generation cap (kW)" />
            <span className="ops-slider-val" style={{ color: AMBER }}>{kwLabel(solarKw)}</span>
          </div>
          <div className="ops-slider-cap">Generation cap</div>
          <div className="ops-tile-controls">
            <DurationChips value={solarDur} onChange={setSolarDur} />
            <button className="ops-btn" onClick={fireSolar}>⚡ Inject</button>
          </div>
          <TileTimeline e={solarEv} placeholder="Fire a real DERControl and watch the hub curtail the inverter to hold the cap." />
        </ScenarioTile>

        {/* ── Demand Response (CSIP import cap + optional home surge) ── */}
        <ScenarioTile icon="⚡" title="Demand Response" sub="utility calls a load-reduction event" accent={BLUE}>
          <div className="ops-slider-row">
            <input className="ops-slider" style={{ accentColor: BLUE }} type="range" min={0.5} max={5} step={0.5} value={drKw} onChange={(e) => setDrKw(Number(e.target.value))} aria-label="Import cap (kW)" />
            <span className="ops-slider-val" style={{ color: BLUE }}>{kwLabel(drKw)}</span>
          </div>
          <div className="ops-slider-cap">Grid import cap</div>
          <label className="ops-toggle">
            <input type="checkbox" checked={surge} onChange={(e) => setSurge(e.target.checked)} />
            <span>+ home surge <span className="ops-toggle-hint">(force the cap to bite)</span></span>
          </label>
          <div className="ops-tile-controls">
            <DurationChips value={drDur} onChange={setDrDur} />
            <button className="ops-btn" onClick={fireDR}>⚡ Inject</button>
          </div>
          <TileTimeline e={drEv} placeholder="The battery answers the event; if import can't clear the cap, the hub reports CannotComply." cannotComply={drCannotComply} />
        </ScenarioTile>

        {/* ── Cloudy Weather (sustained solar sim inject) ── */}
        <ScenarioTile icon="☁︎" title="Cloudy Weather" sub="roll clouds over the array — sustained" accent={AMBER}>
          <div className="ops-slider-row">
            <input className="ops-slider" style={{ accentColor: AMBER }} type="range" min={0} max={100} step={5} value={cloudPct} onChange={(e) => applyCloud(Number(e.target.value))} aria-label="Cloud cover (%)" />
            <span className="ops-slider-val" style={{ color: AMBER }}>{cloudPct}%</span>
          </div>
          <div className="ops-slider-ends"><span>Clear</span><span>Overcast</span></div>
          <div className="ops-tile-controls">
            <span className="ops-readout">
              cloud {liveCloud != null ? `${Math.round(liveCloud)}%` : '—'}
              {solar?.measurements ? ` · solar ${formatWatts(solar.measurements.W_W)}` : ''}
            </span>
            <button className="ops-btn ops-btn-ghost" onClick={clearCloud}>Clear (0%)</button>
          </div>
          <p className="ops-tile-hint">Watch the solar node fade and the hub lean on the battery to hold the plan.</p>
        </ScenarioTile>
      </div>

      {note && <div className="ops-console-note">{note}</div>}
    </div>
  );
}

// ── helpers ─────────────────────────────────────────────────────────────────

/** Compact kW label: "3 kW" / "2.5 kW". */
function kwLabel(kw: number): string {
  return `${kw % 1 === 0 ? kw.toFixed(0) : kw.toFixed(1)} kW`;
}

/** Banner detail for a grid control: "Import ≤ 2.00 kW · enforcing · 1:23 left". */
function gridPillDetail(e: TrackedEvent, expiry: number | null, status?: HubStatus): string {
  const le = evalLimit(e.base, status?.power);
  const cap = le ? le.label : e.label;
  const snow = serverNowS(status);
  const leftS = e.validUntil ? e.validUntil - snow : expiry ? (expiry - Date.now()) / 1000 : 0;
  const phase = e.compliantAt ? 'holding' : e.adoptedAt ? 'enforcing' : 'issued';
  return `${cap} · ${phase} · ${formatCountdown(leftS)} left`;
}

function DurationChips({ value, onChange }: { value: number; onChange: (n: number) => void }) {
  return (
    <div className="ops-dur-chips" role="group" aria-label="Duration">
      {DURATIONS.map((d) => (
        <button key={d} className={`ops-dur-chip${value === d ? ' active' : ''}`} onClick={() => onChange(d)}>{d}s</button>
      ))}
    </div>
  );
}

function ScenarioTile({ icon, title, sub, accent, children }: { icon: string; title: string; sub: string; accent: string; children: ReactNode }) {
  return (
    <div className="ops-tile">
      <div className="ops-tile-head">
        <span className="ops-tile-icon" style={{ color: accent }} aria-hidden>{icon}</span>
        <div>
          <div className="ops-tile-title">{title}</div>
          <div className="ops-tile-sub">{sub}</div>
        </div>
      </div>
      {children}
    </div>
  );
}

function TileTimeline({ e, placeholder, cannotComply }: { e?: TrackedEvent; placeholder: string; cannotComply?: boolean }) {
  if (!e) return <p className="ops-tile-hint">{placeholder}</p>;
  const breach = cannotComply || (e.settled && !e.compliantAt && (e.verdict === 'expired' || e.verdict === 'released'));
  return (
    <div className="ops-tile-track">
      <div className="ops-tile-track-head">
        <span className="ops-tile-track-label">{e.label}</span>
        {breach ? (
          <span className="ops-chip ops-chip-fail">⚠ CannotComply</span>
        ) : e.settled ? (
          verdictChip(e.verdict)
        ) : (
          <span className="ops-chip ops-chip-neutral">tracking…</span>
        )}
      </div>
      <EventTimeline e={e} />
    </div>
  );
}
