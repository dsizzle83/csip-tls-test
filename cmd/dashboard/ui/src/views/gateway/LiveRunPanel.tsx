import { useCallback, useState } from 'react';
import { usePoll } from '../../lib/usePoll';
import { startGwRun, fetchGwRunStatus } from './api';
import type { GwRun } from './types';

// LiveRunPanel — drive the SAME gw-mayhem suite an operator runs by hand,
// straight from the browser, so the proof is reproducible on demand. "Quick"
// runs the curated security set (authz + transport, ~seconds); "Full" runs the
// whole 37-scenario suite (~13 min). Verdict lines stream in as each lands.
export function LiveRunPanel({ onDone }: { onDone?: () => void }) {
  const [busy, setBusy] = useState(false);
  const [startErr, setStartErr] = useState<string | null>(null);

  // Poll the run status only while something is (or was) in flight; the hook
  // pauses on hidden tabs. 1.5s matches the QA cadence used elsewhere.
  const { data: run, refresh } = usePoll<GwRun>(() => fetchGwRunStatus(), 1500);
  const running = run?.state === 'running';

  const kick = useCallback(
    async (mode: 'quick' | 'full') => {
      setStartErr(null);
      setBusy(true);
      try {
        await startGwRun(mode);
        refresh();
      } catch (e) {
        setStartErr(e instanceof Error ? e.message : String(e));
      } finally {
        setBusy(false);
      }
    },
    [refresh]
  );

  // When a run flips to done, let the parent re-pull the saved report.
  const doneSig = run?.state === 'done' ? run?.started_at : undefined;
  if (doneSig && onDone) queueMicrotask(onDone);

  const lines = run?.lines ?? [];

  return (
    <section className="gw-card">
      <header className="gw-card-head">
        <h2>Run the proof live</h2>
        <span className="gw-card-sub">
          drives <span className="gw-mono">scripts/gw-qa-run.sh</span> — pauses the standing aggregator,
          drains the session budget, restores it after
        </span>
      </header>

      <div className="gw-run-actions">
        <button className="gw-btn gw-btn-primary" disabled={busy || running} onClick={() => kick('quick')}>
          {running && run?.mode === 'quick' ? 'Running…' : '▶ Run live proof (quick)'}
        </button>
        <button className="gw-btn" disabled={busy || running} onClick={() => kick('full')}>
          {running && run?.mode === 'full' ? 'Running full suite…' : 'Run full suite (~13 min)'}
        </button>
        {running ? <span className="gw-spin" aria-hidden="true" /> : null}
        {run?.state === 'done' && run.board ? (
          <span className={`gw-run-result ${run.board.gate_green ? 'gw-ok' : 'gw-bad'}`}>
            {run.board.gate_green ? 'GATE PASS' : 'GATE FAIL'} · {run.board.pass} pass
            {run.board.fail ? ` · ${run.board.fail} fail` : ''}
          </span>
        ) : null}
      </div>

      {startErr ? <div className="gw-bad" style={{ fontSize: 12 }}>Could not start: {startErr}</div> : null}
      {run?.state === 'error' ? <div className="gw-bad" style={{ fontSize: 12 }}>Run error: {run.error}</div> : null}

      {lines.length ? (
        <pre className="gw-stream gw-mono">
          {lines.map((l, i) => (
            <div
              key={i}
              className={
                l.startsWith('FAIL') || l.includes('GATE FAIL')
                  ? 'gw-find-bad'
                  : l.startsWith('PASS') || l.startsWith('[PASS]')
                    ? 'gw-find-ok'
                    : ''
              }
            >
              {l}
            </div>
          ))}
        </pre>
      ) : null}
    </section>
  );
}
