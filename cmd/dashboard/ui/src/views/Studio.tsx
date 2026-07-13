import { useEffect, useMemo, useRef, useState } from 'react';
import './studio/studio.css';
import { ApiError } from '../lib/api';
import { fetchScenarios, fetchTariffs, runWhatif } from './studio/api';
import type { Scenario, Tariff, Instruments, WhatifResponse } from './studio/types';
import { ScenarioBuilder } from './studio/ScenarioBuilder';
import { HeroStrip } from './studio/HeroStrip';
import { CostRace } from './studio/CostRace';
import { BillBreakdown } from './studio/BillBreakdown';
import { TouHeatmaps } from './studio/TouHeatmap';
import { DayDetail } from './studio/DayDetail';
import { PlanComparison } from './studio/PlanComparison';
import { ProvenanceCard } from './studio/ProvenanceCard';

// /studio — Savings Studio (the money view). Two-zone layout per DESIGN_BRIEF.md
// §4: scenario-builder rail + results main zone. Backed by GET /api/scenarios,
// GET /api/tariffs, POST /api/whatif/run (CONTRACTS.md §3). Auto-runs once on
// mount with the default scenario so the first paint already shows a result.
export default function Studio() {
  const [scenarios, setScenarios] = useState<Scenario[]>([]);
  const [scnErr, setScnErr] = useState<unknown>(undefined);
  const [scenarioId, setScenarioId] = useState('');
  const [tariffs, setTariffs] = useState<Tariff[]>([]);
  const [tariffsLoading, setTariffsLoading] = useState(false);
  const [tariffIds, setTariffIds] = useState<string[]>([]);
  const [instruments, setInstruments] = useState<Instruments | null>(null);
  const [response, setResponse] = useState<WhatifResponse | null>(null);
  const [runErr, setRunErr] = useState<{ msg: string; status?: number } | null>(null);
  const [running, setRunning] = useState(false);
  const [dirty, setDirty] = useState(false);
  const [focusId, setFocusId] = useState('');

  const runSeq = useRef(0);

  const loadTariffs = (territory: string) => {
    setTariffsLoading(true);
    fetchTariffs(territory)
      .then((list) => setTariffs(list))
      .catch(() => setTariffs([]))
      .finally(() => setTariffsLoading(false));
  };

  const runWith = (sid: string, tids: string[], inst: Instruments) => {
    const seq = ++runSeq.current;
    setRunning(true);
    setRunErr(null);
    runWhatif({ scenario_id: sid, tariff_ids: tids, instruments: inst })
      .then((resp) => {
        if (seq !== runSeq.current) return; // a newer run superseded this one
        setResponse(resp);
        setDirty(false);
      })
      .catch((e) => {
        if (seq !== runSeq.current) return;
        if (e instanceof ApiError) {
          const body = e.body as { error?: string } | undefined;
          setRunErr({ msg: body?.error ?? e.message, status: e.status });
        } else {
          setRunErr({ msg: e instanceof Error ? e.message : String(e) });
        }
      })
      .finally(() => {
        if (seq === runSeq.current) setRunning(false);
      });
  };

  const selectScenario = (scn: Scenario) => {
    const tids = scn.tariff_ids.slice(0, 4);
    setScenarioId(scn.id);
    setTariffIds(tids);
    setInstruments(scn.instrument_defaults);
    setFocusId(
      scn.default_tariff_id && tids.includes(scn.default_tariff_id)
        ? scn.default_tariff_id
        : tids[0]
    );
    loadTariffs(scn.location.territory);
    runWith(scn.id, tids, scn.instrument_defaults);
  };

  // Load scenarios once; auto-run the first with its defaults.
  useEffect(() => {
    let cancelled = false;
    fetchScenarios()
      .then((list) => {
        if (cancelled) return;
        setScenarios(list);
        if (list.length) selectScenario(list[0]);
      })
      .catch((e) => {
        if (!cancelled) setScnErr(e);
      });
    return () => {
      cancelled = true;
    };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  const onToggleTariff = (id: string) => {
    setTariffIds((prev) => {
      if (prev.includes(id)) {
        if (prev.length <= 1) return prev; // keep at least one
        return prev.filter((x) => x !== id);
      }
      if (prev.length >= 4) return prev;
      return [...prev, id];
    });
    setDirty(true);
  };

  const onInstruments = (next: Instruments) => {
    setInstruments(next);
    setDirty(true);
  };

  // Which tariffs the current results actually cover (decoupled from any
  // pending, not-yet-run selection change).
  const respTariffIds = useMemo(
    () => (response ? [...new Set(response.runs.map((r) => r.tariff_id))] : []),
    [response]
  );
  const focusTariffId = useMemo(() => {
    if (respTariffIds.includes(focusId)) return focusId;
    const def = response?.scenario.default_tariff_id ?? '';
    return respTariffIds.includes(def) ? def : respTariffIds[0] ?? '';
  }, [respTariffIds, focusId, response]);

  const shownTariffs = useMemo(
    () =>
      respTariffIds
        .map((id) => tariffs.find((t) => t.id === id))
        .filter((t): t is Tariff => Boolean(t)),
    [respTariffIds, tariffs]
  );
  const dates = response?.runs[0]?.daily.dates ?? [];

  const selScenario = scenarios.find((s) => s.id === scenarioId);

  return (
    <div className="view-stack">
      <h1 className="page-title">Savings Studio</h1>

      {scnErr ? (
        <div className="st-error">
          <strong>Could not load scenarios</strong>
          The what-if backend is unreachable. Confirm the dashboard is serving /api/scenarios.
        </div>
      ) : null}

      <div className="studio">
        {/* left rail */}
        {instruments && selScenario ? (
          <ScenarioBuilder
            scenarios={scenarios}
            selectedScenarioId={scenarioId}
            onSelectScenario={(id) => {
              const scn = scenarios.find((s) => s.id === id);
              if (scn) selectScenario(scn);
            }}
            tariffs={tariffs}
            tariffsLoading={tariffsLoading}
            selectedTariffIds={tariffIds}
            onToggleTariff={onToggleTariff}
            instruments={instruments}
            onInstruments={onInstruments}
            onRun={() => runWith(scenarioId, tariffIds, instruments)}
            running={running}
            dirty={dirty}
          />
        ) : (
          <div className="st-rail">
            <div className="st-skel" style={{ height: 180 }} />
            <div className="st-skel" style={{ height: 140 }} />
            <div className="st-skel" style={{ height: 260 }} />
          </div>
        )}

        {/* main zone */}
        <div className="st-main">
          {runErr ? (
            <div className="st-error">
              <strong>
                {runErr.status === 422
                  ? 'Plan / scenario mismatch'
                  : runErr.status === 400
                    ? 'Invalid request'
                    : 'Could not run the simulation'}
              </strong>
              {runErr.msg}
            </div>
          ) : null}

          {!response ? (
            running ? (
              <>
                <div className="st-skel" style={{ height: 118 }} />
                <div className="st-skel" style={{ height: 300 }} />
                <div className="st-skel" style={{ height: 220 }} />
              </>
            ) : (
              !runErr && (
                <p className="empty-state">Pick a location and plans, then run the savings model.</p>
              )
            )
          ) : (
            <div className={running ? 'st-dim' : undefined}>
              <div className="st-main">
                {running ? (
                  <div className="st-updating">
                    <span className="st-run-bolt">⚡</span> Recalculating…
                  </div>
                ) : null}

                <HeroStrip response={response} focusTariffId={focusTariffId} tariffs={tariffs} />

                {shownTariffs.length > 1 ? (
                  <div className="st-focus">
                    <span className="st-focus-lbl">Focus plan</span>
                    {shownTariffs.map((t) => (
                      <button
                        key={t.id}
                        className={`st-pill${t.id === focusTariffId ? ' active' : ''}`}
                        onClick={() => setFocusId(t.id)}
                      >
                        {t.short_name || t.name}
                      </button>
                    ))}
                  </div>
                ) : null}

                <div className="st-card">
                  <div className="st-card-head">
                    <h2 className="card-title">Cumulative cost race</h2>
                    <div className="st-head-meta">running monthly bill, day by day</div>
                  </div>
                  <CostRace response={response} focusTariffId={focusTariffId} />
                </div>

                <BillBreakdown response={response} focusTariffId={focusTariffId} />

                <TouHeatmaps tariffs={shownTariffs} dates={dates} />

                <DayDetail response={response} focusTariffId={focusTariffId} />

                <PlanComparison response={response} tariffs={shownTariffs} />

                <ProvenanceCard response={response} tariffs={tariffs} />
              </div>
            </div>
          )}
        </div>
      </div>
    </div>
  );
}
