// Safety case strip (brief §4.1): the investor headline. Four invariant cards
// (SOC/CONNECT/EXPORT/EXPIRED) + a compact row (EVMAX/HUNT/CONVERGE). Each card
// states the invariant in plain language and shows its status from the most
// recent run's findings — icon + label, never color alone.

import { HEADLINE_INVARIANTS, COMPACT_INVARIANTS, invStatus } from './verdict';
import type { InvState, InvariantDef } from './verdict';
import { verdictMeta } from './verdict';
import type { MayFinding } from './types';
import type { ReportSummary } from './markdown';
import { formatDate } from '../../lib/format';

function StatusBadge({ st, guardCount }: { st: InvState; guardCount: number }) {
  if (st.state === 'idle') {
    return (
      <span className="pf-inv-status" style={{ color: 'var(--s-neutral)' }} title="No campaign has exercised this invariant in this session">
        <span aria-hidden="true">○</span> Not run
      </span>
    );
  }
  if (st.state === 'held') {
    const m = verdictMeta('PASS');
    return (
      <span className="pf-inv-status" style={{ color: `var(${m.cssVar})` }} title={`Held across ${st.scenarios} scenarios`}>
        <span aria-hidden="true">{m.icon}</span> Held · {guardCount}
      </span>
    );
  }
  const m = verdictMeta(st.verdict);
  return (
    <span className="pf-inv-status" style={{ color: `var(${m.cssVar})` }} title={`Worst: ${m.label} in ${st.byId}`}>
      <span aria-hidden="true">{m.icon}</span> {m.label}
    </span>
  );
}

function InvCard({
  def,
  findings,
  guardCount,
}: {
  def: InvariantDef;
  findings: MayFinding[];
  guardCount: number;
}) {
  const st = invStatus(def, findings);
  return (
    <div className="pf-inv-card">
      <div className="pf-inv-top">
        <span className="pf-inv-id">{def.id}</span>
        <StatusBadge st={st} guardCount={guardCount} />
      </div>
      <span className="pf-inv-short">{def.short}</span>
      <span className="pf-inv-line">{def.line}</span>
      <span className="pf-inv-caption">
        {def.kind === 'audit' ? 'Guarded on every scenario' : 'Primary oracle of the export/limit scenarios'}
      </span>
    </div>
  );
}

function CompactItem({
  def,
  findings,
  guardCount,
}: {
  def: InvariantDef;
  findings: MayFinding[];
  guardCount: number;
}) {
  const st = invStatus(def, findings);
  return (
    <div className="pf-compact-item" title={def.line}>
      <div className="pf-compact-top">
        <span className="pf-inv-id">{def.id}</span>
        <StatusBadge st={st} guardCount={guardCount} />
      </div>
      <span className="pf-inv-short" style={{ fontSize: 12 }}>
        {def.short}
      </span>
    </div>
  );
}

export function SafetyCaseStrip({
  findings,
  scenarioCount,
  lastReport,
}: {
  findings: MayFinding[];
  scenarioCount: number;
  lastReport: ReportSummary | null;
}) {
  const invCount = HEADLINE_INVARIANTS.length + COMPACT_INVARIANTS.length; // 7
  return (
    <div className="pf-card">
      <div className="pf-safety-lead">
        <span className="pf-safety-headline">
          <b>{scenarioCount}</b> adversarial hardware-in-the-loop scenarios guard <b>{invCount}</b> safety invariants.
        </span>
        {findings.length === 0 && lastReport && (
          <span className="pf-provenance">
            Last campaign{lastReport.startedAt ? ` ${formatDate(lastReport.startedAt)}` : ''}: {lastReport.pass} pass · {lastReport.fail} fail · {lastReport.blind} blind
          </span>
        )}
        {findings.length === 0 && !lastReport && (
          <span className="pf-provenance">Not exercised this session — run a campaign below.</span>
        )}
      </div>

      <div className="pf-inv-grid">
        {HEADLINE_INVARIANTS.map((def) => (
          <InvCard key={def.id} def={def} findings={findings} guardCount={scenarioCount} />
        ))}
      </div>

      <div className="pf-compact-row">
        {COMPACT_INVARIANTS.map((def) => (
          <CompactItem key={def.id} def={def} findings={findings} guardCount={scenarioCount} />
        ))}
      </div>
    </div>
  );
}
