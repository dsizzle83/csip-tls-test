import { useEffect, useRef, useState } from 'react';
import './proof/proof.css';
import { usePoll } from '../lib/usePoll';
import { fetchScenarios, fetchStatus, fetchReports, fetchReportMarkdown } from './proof/api';
import { parseReportSummary } from './proof/markdown';
import type { ReportSummary } from './proof/markdown';
import type { ScenarioInfo, MayhemStatus } from './proof/types';
import { QUICK_SWEEP_IDS } from './proof/verdict';
import { SafetyCaseStrip } from './proof/SafetyCaseStrip';
import { ScenarioBrowser } from './proof/ScenarioBrowser';
import { RunPanel } from './proof/RunPanel';
import { FindingsList } from './proof/FindingsList';
import { HistoryCard } from './proof/HistoryCard';

// /proof — Proof Center (DESIGN_BRIEF.md §4). Safety case strip → scenario
// browser → run panel (with the live real-vs-hub timeline) → findings →
// history. Backed by /api/qa/scenarios, /api/qa/{start,abort,status}, and
// /api/qa/reports (CONTRACTS.md §6). status is polled at the brief's 1.5 s QA
// cadence; findings + the safety strip persist between runs.
export default function Proof() {
  const { data: scenarios, error: scnError } = usePoll<ScenarioInfo[]>(() => fetchScenarios(), 60000);
  const { data: status, refresh } = usePoll<MayhemStatus>(() => fetchStatus(), 1500);

  const [selected, setSelected] = useState<Set<string>>(new Set());
  const seededRef = useRef(false);

  // Seed the Quick-sweep preset once the catalogue lands (only once — a user
  // clearing the selection is never re-seeded).
  useEffect(() => {
    if (seededRef.current || !scenarios || scenarios.length === 0) return;
    const avail = new Set(scenarios.map((s) => s.id));
    setSelected(new Set(QUICK_SWEEP_IDS.filter((id) => avail.has(id))));
    seededRef.current = true;
  }, [scenarios]);

  // Newest report summary — provenance for the safety strip when no run has
  // happened this session. Re-fetched when a run finishes (report_path changes).
  const [lastReport, setLastReport] = useState<ReportSummary | null>(null);
  const reportPath = status?.report_path;
  useEffect(() => {
    let cancelled = false;
    fetchReports()
      .then(async (reps) => {
        if (cancelled) return;
        if (!reps.length) {
          setLastReport(null);
          return;
        }
        const md = await fetchReportMarkdown(reps[0].name);
        if (!cancelled) setLastReport(parseReportSummary(md));
      })
      .catch(() => {
        /* history card surfaces report errors; strip just omits provenance */
      });
    return () => {
      cancelled = true;
    };
  }, [reportPath]);

  const findings = status?.findings ?? [];

  return (
    <div className="view-stack">
      <h1 className="page-title">Proof Center</h1>

      {scnError ? (
        <div style={{ color: 'var(--s-warn)', fontSize: 12 }}>
          Could not reach the QA backend — showing an empty catalogue.
        </div>
      ) : null}

      <SafetyCaseStrip findings={findings} scenarioCount={scenarios?.length ?? 0} lastReport={lastReport} />

      <ScenarioBrowser scenarios={scenarios ?? []} selected={selected} onSelectedChange={setSelected} />

      <RunPanel status={status} selected={selected} scenarios={scenarios ?? []} onRefresh={refresh} />

      <FindingsList findings={findings} />

      <HistoryCard />
    </div>
  );
}
