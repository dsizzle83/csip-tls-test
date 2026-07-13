// Findings list (brief §4.4): one card per scenario verdict, with metric chips,
// an expandable diagnosis + fix, and — when the finding carries safety-audit
// violations[] — a mini timeline strip (x = t_s, one lane per invariant, dots
// in the finding's verdict color, tooltip = detail).

import { useMemo, useState } from 'react';
import type { EChartsOption } from 'echarts';
import { EChart } from '../../lib/echart';
import { token } from '../../lib/colors';
import { formatWatts, formatDuration } from '../../lib/format';
import type { MayFinding, InvViolation } from './types';
import { VerdictChip, MetricChip } from './chips';
import { verdictColor } from './verdict';

function boolChip(label: string, v: boolean) {
  return <MetricChip key={label} label={label} value={v ? 'yes' : 'no'} />;
}

function ViolationStrip({ violations, color }: { violations: InvViolation[]; color: string }) {
  const lanes = useMemo(() => Array.from(new Set(violations.map((v) => v.inv))), [violations]);
  const maxT = useMemo(() => Math.max(1, ...violations.map((v) => v.t_s)), [violations]);
  const option = useMemo<EChartsOption>(() => {
    const ink3 = token('--ink-3');
    return {
      grid: { left: 96, right: 20, top: 10, bottom: 24 },
      tooltip: {
        trigger: 'item',
        formatter: (raw: unknown) => {
          const p = raw as { data: { detail: string; value: [number, string] } };
          return `<b>${p.data.value[1]}</b> · t=${p.data.value[0].toFixed(0)}s<br/>${p.data.detail}`;
        },
      },
      xAxis: {
        type: 'value',
        min: 0,
        max: Math.ceil(maxT * 1.05),
        name: 's',
        nameTextStyle: { color: ink3, fontSize: 10 },
        axisLabel: { color: ink3, fontSize: 10, formatter: (v: number) => `${Math.round(v)}` },
      },
      yAxis: {
        type: 'category',
        data: lanes,
        axisLabel: { color: token('--ink-2'), fontSize: 10, fontFamily: 'ui-monospace, monospace' },
        axisTick: { show: false },
      },
      series: [
        {
          type: 'scatter',
          symbolSize: 9,
          data: violations.map((v) => ({ value: [v.t_s, v.inv], detail: v.detail })),
          itemStyle: { color, opacity: 0.85 },
        },
      ],
    };
  }, [violations, lanes, maxT, color]);

  return (
    <div>
      <div className="pf-viol-strip-title">
        Safety-audit violations · {violations.length} across {lanes.length} invariant{lanes.length > 1 ? 's' : ''}
      </div>
      <EChart option={option} style={{ height: lanes.length * 26 + 44 }} />
    </div>
  );
}

function FindingCard({ f }: { f: MayFinding }) {
  const [open, setOpen] = useState(false);
  const m = f.metrics;
  const color = verdictColor(f.verdict);
  return (
    <div className="pf-finding">
      <div className="pf-finding-head">
        <VerdictChip verdict={f.verdict} />
        <span className="pf-finding-name">{f.name}</span>
        <span className="pf-scn-id">{f.id}</span>
      </div>
      <div className="pf-finding-headline">{f.headline}</div>

      <div className="pf-metric-chips">
        <MetricChip label="peak" value={m.peak_breach_W > 0 ? formatWatts(m.peak_breach_W) : '—'} />
        <MetricChip label="breach" value={m.breach_seconds > 0 ? formatDuration(m.breach_seconds) : '0s'} />
        <MetricChip label="recovery" value={m.recovery_seconds >= 0 ? formatDuration(m.recovery_seconds) : 'n/a'} />
        {boolChip('adopted', m.hub_adopted)}
        {boolChip('reacted', m.hub_reacted)}
        {boolChip('blind', m.hub_blind)}
        {boolChip('cannot-comply', m.reported_cannot_comply)}
      </div>

      {f.violations && f.violations.length > 0 && <ViolationStrip violations={f.violations} color={color} />}

      {/* The backend still emits the safety audit as a prose bullet (legacy
          report compatibility); the ViolationStrip above renders the same
          data structurally, so drop the redundant bullet here. */}
      {(() => {
        const diag =
          f.violations && f.violations.length > 0
            ? f.diagnosis.filter((d) => !d.includes('SAFETY AUDIT'))
            : f.diagnosis;
        return (
          <>
            {(diag.length > 0 || f.fix) && (
        <button
          type="button"
          onClick={() => setOpen((o) => !o)}
          style={{ fontSize: 12, color: 'var(--ink-2)', background: 'none', border: 'none', cursor: 'pointer', padding: '2px 0', display: 'flex', alignItems: 'center', gap: 5, alignSelf: 'flex-start' }}
        >
          <span aria-hidden="true">{open ? '▾' : '▸'}</span>
          {open ? 'Hide diagnosis' : 'Diagnosis & fix'}
        </button>
      )}
            {open && (
              <div>
                {diag.length > 0 && (
                  <ul className="pf-diag">
                    {diag.map((d, i) => (
                      <li key={i}>{d}</li>
                    ))}
                  </ul>
                )}
                {f.fix && <div className="pf-fix">Where to look: {f.fix}</div>}
              </div>
            )}
          </>
        );
      })()}
    </div>
  );
}

export function FindingsList({ findings }: { findings: MayFinding[] }) {
  if (findings.length === 0) return null;
  return (
    <div className="pf-card">
      <div className="pf-card-head">
        <h2 className="card-title">Findings</h2>
        <span className="pf-head-meta">{findings.length} scenarios diagnosed</span>
      </div>
      {findings.map((f) => (
        <FindingCard key={f.id} f={f} />
      ))}
    </div>
  );
}
