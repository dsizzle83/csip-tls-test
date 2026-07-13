// Left rail (DESIGN_BRIEF.md §4): scenario cards → tariff multi-select (1–4)
// with confidence badges → instrument sliders/inputs → Run button. Fully
// controlled; the parent owns the state and fires the run.

import { ConfidenceBadge } from './badges';
import type { Scenario, Tariff, Instruments } from './types';

function Slider({
  label,
  value,
  min,
  max,
  step,
  unit,
  disabled,
  onChange,
}: {
  label: string;
  value: number;
  min: number;
  max: number;
  step: number;
  unit: string;
  disabled?: boolean;
  onChange: (v: number) => void;
}) {
  return (
    <div className="st-ctrl">
      <div className="st-ctrl-head">
        <span className="st-ctrl-label">{label}</span>
        <span className="st-ctrl-val">
          {value}
          {unit ? ` ${unit}` : ''}
        </span>
      </div>
      <input
        className="st-range"
        type="range"
        min={min}
        max={max}
        step={step}
        value={value}
        disabled={disabled}
        onChange={(e) => onChange(Number(e.target.value))}
      />
    </div>
  );
}

export function ScenarioBuilder({
  scenarios,
  selectedScenarioId,
  onSelectScenario,
  tariffs,
  tariffsLoading,
  selectedTariffIds,
  onToggleTariff,
  instruments,
  onInstruments,
  onRun,
  running,
  dirty,
}: {
  scenarios: Scenario[];
  selectedScenarioId: string;
  onSelectScenario: (id: string) => void;
  tariffs: Tariff[];
  tariffsLoading: boolean;
  selectedTariffIds: string[];
  onToggleTariff: (id: string) => void;
  instruments: Instruments;
  onInstruments: (next: Instruments) => void;
  onRun: () => void;
  running: boolean;
  dirty: boolean;
}) {
  const selCount = selectedTariffIds.length;
  const batt = instruments.battery;
  const ev = instruments.ev;

  // Immutable nested setters.
  const setPv = (pv_kw: number) => onInstruments({ ...instruments, pv_kw });
  const setBatt = (patch: Partial<Instruments['battery']>) =>
    onInstruments({ ...instruments, battery: { ...batt, ...patch } });
  const setEv = (patch: Partial<Instruments['ev']>) =>
    onInstruments({ ...instruments, ev: { ...ev, ...patch } });

  return (
    <div className="st-rail">
      {/* location / scenario */}
      <div className="st-card">
        <div className="st-rail-section">
          <span className="st-rail-label">Location</span>
          <div className="st-scn-cards">
            {scenarios.map((s) => (
              <button
                key={s.id}
                className={`st-scn${s.id === selectedScenarioId ? ' active' : ''}`}
                onClick={() => onSelectScenario(s.id)}
              >
                <div className="st-scn-city">
                  {s.location.city}, {s.location.state}
                </div>
                <div className="st-scn-blurb">{s.location.blurb}</div>
                <div className="st-scn-terr">
                  {s.location.territory} · {s.period.start} – {s.period.end}
                </div>
              </button>
            ))}
          </div>
        </div>
      </div>

      {/* tariffs */}
      <div className="st-card">
        <div className="st-rail-section">
          <span className="st-rail-label">
            Plans <span style={{ color: 'var(--ink-3)', fontWeight: 400 }}>({selCount}/4)</span>
          </span>
          <div className="st-chips">
            {tariffsLoading && tariffs.length === 0 ? (
              <div style={{ fontSize: 12, color: 'var(--ink-3)', padding: '6px 2px' }}>
                Loading plans…
              </div>
            ) : (
              tariffs.map((t) => {
                const active = selectedTariffIds.includes(t.id);
                const blockAdd = !active && selCount >= 4;
                return (
                  <button
                    key={t.id}
                    className={`st-chip${active ? ' active' : ''}`}
                    disabled={blockAdd || (active && selCount === 1)}
                    onClick={() => onToggleTariff(t.id)}
                    title={active && selCount === 1 ? 'At least one plan must stay selected' : undefined}
                  >
                    <span className="st-chip-check">{active ? '✓' : ''}</span>
                    <span className="st-chip-body">
                      <span className="st-chip-name">{t.short_name || t.name}</span>
                      <span className="st-chip-util">{t.utility}</span>
                    </span>
                    <ConfidenceBadge
                      confidence={t.provenance.confidence}
                      sourceUrl={t.provenance.source_url}
                      retrieved={t.provenance.retrieved}
                    />
                  </button>
                );
              })
            )}
          </div>
        </div>
      </div>

      {/* instruments */}
      <div className="st-card">
        <div className="st-rail-section">
          <span className="st-rail-label">Your system</span>
          <div className="st-inst">
            <Slider
              label="Solar PV"
              value={instruments.pv_kw}
              min={0}
              max={16}
              step={0.5}
              unit="kW"
              onChange={setPv}
            />
            <div className="st-two">
              <Slider
                label="Battery"
                value={batt.kwh}
                min={0}
                max={27}
                step={0.5}
                unit="kWh"
                onChange={(kwh) => setBatt({ kwh })}
              />
              <Slider
                label="Power"
                value={batt.kw}
                min={0}
                max={10}
                step={0.5}
                unit="kW"
                onChange={(kw) => setBatt({ kw })}
              />
            </div>
            <Slider
              label="Reserve floor"
              value={batt.reserve_pct}
              min={0}
              max={100}
              step={5}
              unit="%"
              disabled={batt.kwh === 0}
              onChange={(reserve_pct) => setBatt({ reserve_pct })}
            />

            <div className="st-toggle-row">
              <label className="st-switch">
                <input
                  type="checkbox"
                  checked={ev.present}
                  onChange={(e) => setEv({ present: e.target.checked })}
                />
                Electric vehicle
              </label>
            </div>
            {ev.present ? (
              <div className="st-ev-grid">
                <div className="st-field">
                  <label>Commute kWh/day</label>
                  <input
                    className="st-num"
                    type="number"
                    min={0}
                    max={80}
                    step={1}
                    value={ev.weekday_kwh}
                    onChange={(e) => setEv({ weekday_kwh: Number(e.target.value) })}
                  />
                </div>
                <div className="st-field">
                  <label>Charger kW</label>
                  <input
                    className="st-num"
                    type="number"
                    min={1}
                    max={19.2}
                    step={0.1}
                    value={ev.charger_kw}
                    onChange={(e) => setEv({ charger_kw: Number(e.target.value) })}
                  />
                </div>
                <div className="st-field">
                  <label>Depart hour</label>
                  <input
                    className="st-num"
                    type="number"
                    min={0}
                    max={23}
                    step={1}
                    value={ev.depart_hour}
                    onChange={(e) => setEv({ depart_hour: Number(e.target.value) })}
                  />
                </div>
                <div className="st-field">
                  <label>Return hour</label>
                  <input
                    className="st-num"
                    type="number"
                    min={0}
                    max={23}
                    step={1}
                    value={ev.return_hour}
                    onChange={(e) => setEv({ return_hour: Number(e.target.value) })}
                  />
                </div>
              </div>
            ) : null}
          </div>
        </div>

        <button className="st-run" onClick={onRun} disabled={running} style={{ marginTop: 18 }}>
          <span className="st-run-bolt">⚡</span>
          {running ? 'Running…' : 'Run savings'}
        </button>
        {dirty && !running ? (
          <div className="st-dirty">Inputs changed — run to update results</div>
        ) : null}
      </div>
    </div>
  );
}
