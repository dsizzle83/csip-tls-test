// Run panel (brief §4.3): start/abort a campaign, show live progress + phase +
// an accumulating verdict scoreboard, and host the live timeline while a run is
// in flight. The status poll lives in Proof.tsx; this panel just drives actions
// and renders what the poll returns.

import { useState } from 'react';
import type { MayhemStatus, ScenarioInfo, Verdict } from './types';
import { startRun, abortRun } from './api';
import { VerdictChip } from './chips';
import { LiveTimeline } from './LiveTimeline';

const CADENCES = [
  { ms: 500, label: '0.5 s (fine)' },
  { ms: 1000, label: '1 s (default)' },
  { ms: 2000, label: '2 s (coarse)' },
];

const PHASE_ICON: Record<string, string> = { setup: '⚙', hold: '⏱', recover: '↩', done: '✓' };

function phaseLabel(phase: string): string {
  return phase ? phase.charAt(0).toUpperCase() + phase.slice(1) : '—';
}

export function RunPanel({
  status,
  selected,
  scenarios,
  onRefresh,
}: {
  status: MayhemStatus | undefined;
  selected: Set<string>;
  scenarios: ScenarioInfo[];
  onRefresh: () => void;
}) {
  const [sampleMs, setSampleMs] = useState(1000);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const running = status?.running ?? false;
  const extById = new Map(scenarios.map((s) => [s.id, s.extended]));
  const includeExtended = Array.from(selected).some((id) => extById.get(id));

  const start = async () => {
    setError(null);
    setBusy(true);
    try {
      await startRun({ only: Array.from(selected), sample_ms: sampleMs, include_extended: includeExtended });
      // Give the driver a moment to flip status.running before we re-poll.
      setTimeout(onRefresh, 400);
    } catch (e) {
      setError(e instanceof Error ? e.message : String(e));
    } finally {
      setBusy(false);
    }
  };

  const abort = async () => {
    setBusy(true);
    try {
      await abortRun();
      setTimeout(onRefresh, 400);
    } catch (e) {
      setError(e instanceof Error ? e.message : String(e));
    } finally {
      setBusy(false);
    }
  };

  const summary = status?.summary;
  const verdictOrder: Verdict[] = ['PASS', 'DEGRADED', 'BLIND', 'FAIL', 'INCONCLUSIVE'];
  const summaryCount = (v: Verdict): number => {
    if (!summary) return 0;
    return {
      PASS: summary.pass,
      DEGRADED: summary.degraded,
      BLIND: summary.blind,
      FAIL: summary.fail,
      INCONCLUSIVE: summary.inconclusive,
    }[v];
  };
  const anyVerdicts = verdictOrder.some((v) => summaryCount(v) > 0);

  return (
    <div className="pf-card">
      <div className="pf-card-head">
        <h2 className="card-title">Run a campaign</h2>
        <span className="pf-head-meta">{selected.size} scenarios selected{includeExtended ? ' · incl. extended' : ''}</span>
      </div>

      <div className="pf-run-head">
        {!running ? (
          <>
            <button type="button" className="pf-btn pf-btn-primary" onClick={start} disabled={busy || selected.size === 0}>
              ⚡ Start {selected.size > 0 ? `· ${selected.size}` : ''}
            </button>
            <label style={{ fontSize: 12, color: 'var(--ink-2)', display: 'inline-flex', alignItems: 'center', gap: 6 }}>
              Sample
              <select className="pf-select" value={sampleMs} onChange={(e) => setSampleMs(Number(e.target.value))}>
                {CADENCES.map((c) => (
                  <option key={c.ms} value={c.ms}>
                    {c.label}
                  </option>
                ))}
              </select>
            </label>
            {selected.size === 0 && <span className="pf-count-note">select scenarios above to enable</span>}
          </>
        ) : (
          <>
            <button type="button" className="pf-btn pf-btn-danger" onClick={abort} disabled={busy}>
              ■ Abort
            </button>
            <span className="pf-phase">
              <span aria-hidden="true">{PHASE_ICON[status?.phase ?? ''] ?? '•'}</span> {phaseLabel(status?.phase ?? '')}
            </span>
            <span className="pf-run-current">
              {status?.current || '…'}
              {status?.current_id && <span className="pf-scn-id">{status.current_id}</span>}
            </span>
          </>
        )}
      </div>

      {error && <div style={{ color: 'var(--s-critical)', fontSize: 12, marginTop: 8 }}>{error}</div>}

      {running && status && (
        <>
          <div className="pf-progress" title={`${status.pct.toFixed(0)}%`}>
            <div className="pf-progress-fill" style={{ width: `${Math.max(2, Math.min(100, status.pct))}%` }} />
          </div>
          <div style={{ display: 'flex', justifyContent: 'space-between', fontSize: 12, color: 'var(--ink-2)' }}>
            <span>
              Scenario {status.idx} of {status.total}
            </span>
            <span className="mono">{status.pct.toFixed(0)}%</span>
          </div>
        </>
      )}

      {anyVerdicts && (
        <div className="pf-verdict-pills" style={{ marginTop: 12 }}>
          {verdictOrder.map((v) => {
            const c = summaryCount(v);
            if (c === 0) return null;
            return <VerdictChip key={v} verdict={v} count={c} />;
          })}
          {summary && summary.worst_peak_breach_W > 0 && (
            <span className="pf-count-note" style={{ marginLeft: 4 }}>
              worst breach {(summary.worst_peak_breach_W / 1000).toFixed(2)} kW
            </span>
          )}
        </div>
      )}

      {running && status && (
        <div style={{ marginTop: 14 }}>
          <LiveTimeline samples={status.live ?? []} />
        </div>
      )}
    </div>
  );
}
