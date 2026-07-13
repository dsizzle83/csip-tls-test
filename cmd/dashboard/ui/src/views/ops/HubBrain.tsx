import { useEffect, useRef, useState } from 'react';
import { formatClock } from '../../lib/format';
import type { HubDecision, HubStatus } from './types';

// Hub brain (brief §4.2): the live decisions feed. The hub only ever exposes
// the LATEST plan's decisions in status.last_plan, so we keep a bounded
// rolling client-side history (200 rows) and append a plan's decisions only
// when their content changes (dedupe consecutive identical plans).

const MAX_ROWS = 200;

interface FeedRow {
  id: number;
  planTs: string;
  rule: string;
  reason: string;
  impact: string;
}

function planSignature(planTs: string, decisions: HubDecision[]): string {
  return planTs + '|' + decisions.map((d) => `${d.rule}~${d.reason}~${d.impact}`).join('||');
}

export function HubBrain({ status }: { status?: HubStatus }) {
  const [rows, setRows] = useState<FeedRow[]>([]);
  const lastSig = useRef<string>('');
  const idRef = useRef(0);

  useEffect(() => {
    const plan = status?.last_plan;
    if (!plan || !plan.decisions || plan.decisions.length === 0) return;
    const sig = planSignature(plan.timestamp, plan.decisions);
    if (sig === lastSig.current) return;
    lastSig.current = sig;
    const newRows: FeedRow[] = plan.decisions.map((d) => ({
      id: idRef.current++,
      planTs: plan.timestamp,
      rule: d.rule,
      reason: d.reason,
      impact: d.impact,
    }));
    setRows((prev) => [...newRows, ...prev].slice(0, MAX_ROWS));
  }, [status]);

  const mode = status?.mode;
  const stale = status?.stale_sources ?? [];

  return (
    <div className="ops-card">
      <div className="ops-card-head">
        <h2 className="card-title">Hub Brain</h2>
        <div className="ops-brain-badges">
          {mode && <span className="ops-chip ops-chip-mode">{mode}</span>}
          <span className="ops-head-meta">{rows.length ? `${rows.length} decisions` : ''}</span>
        </div>
      </div>

      {stale.length > 0 && (
        <div className="ops-stale-row">
          {stale.map((s) => (
            <span key={s} className="ops-chip ops-chip-warn" title="Stale telemetry source">
              <span aria-hidden>⚠</span> {s}
            </span>
          ))}
        </div>
      )}

      {rows.length === 0 ? (
        <p className="ops-empty">The hub hasn&apos;t logged a decision yet. Fire a grid event below to watch it reason in real time.</p>
      ) : (
        <div className="ops-feed">
          {rows.map((r, i) => {
            const showTime = i === 0 || rows[i - 1].planTs !== r.planTs;
            return (
              <div className="ops-feed-row" key={r.id}>
                <span className="ops-chip ops-chip-rule" title="Decision rule">{r.rule}</span>
                <div className="ops-feed-body">
                  <span className="ops-feed-reason">{r.reason}</span>
                  <span className="ops-feed-arrow">→</span>
                  <span className="ops-feed-impact">{r.impact}</span>
                  {showTime && <div className="ops-feed-time">{formatClock(r.planTs)}</div>}
                </div>
              </div>
            );
          })}
        </div>
      )}
    </div>
  );
}
