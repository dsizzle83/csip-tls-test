// History (brief §4.5): past campaign reports from /api/qa/reports. Click a row
// to fetch its markdown and read it in a modal (rendered by our dependency-free
// renderMarkdown). When ≥3 reports carry a parseable summary line we draw a
// pass-rate trend; if the summaries aren't parseable we say so and show the list
// only — never a faked trend.

import { useEffect, useMemo, useState } from 'react';
import type { EChartsOption } from 'echarts';
import { EChart } from '../../lib/echart';
import { usePoll } from '../../lib/usePoll';
import { token } from '../../lib/colors';
import { formatDate, formatClock } from '../../lib/format';
import { fetchReports, fetchReportMarkdown } from './api';
import { parseReportSummary } from './markdown';
import type { ReportSummary } from './markdown';
import { renderMarkdown } from './markdown';
import type { QAReportEntry } from './types';

function prettyBytes(n: number): string {
  if (n < 1024) return `${n} B`;
  return `${(n / 1024).toFixed(1)} KB`;
}

// Report name: qa-mayhem-YYYYMMDD-HHMMSS.md → a friendly label.
function reportLabel(name: string, mtime: string): string {
  const m = /qa-mayhem-(\d{4})(\d{2})(\d{2})-(\d{2})(\d{2})(\d{2})\.md/.exec(name);
  if (m) {
    const d = new Date(Date.UTC(+m[1], +m[2] - 1, +m[3], +m[4], +m[5], +m[6]));
    return `${formatDate(d)} ${formatClock(d)}`;
  }
  return `${formatDate(mtime)} ${formatClock(mtime)}`;
}

function ReportModal({ name, onClose }: { name: string; onClose: () => void }) {
  const [md, setMd] = useState<string | null>(null);
  const [err, setErr] = useState<string | null>(null);

  useEffect(() => {
    const ctrl = new AbortController();
    fetchReportMarkdown(name, ctrl.signal)
      .then(setMd)
      .catch((e) => setErr(e instanceof Error ? e.message : String(e)));
    const onKey = (e: KeyboardEvent) => {
      if (e.key === 'Escape') onClose();
    };
    window.addEventListener('keydown', onKey);
    return () => {
      ctrl.abort();
      window.removeEventListener('keydown', onKey);
    };
  }, [name, onClose]);

  return (
    <div className="pf-modal-backdrop" onClick={onClose}>
      <div className="pf-modal" onClick={(e) => e.stopPropagation()}>
        <div className="pf-modal-head">
          <span className="pf-report-name">{name}</span>
          <button type="button" className="pf-modal-close" onClick={onClose} aria-label="close">
            ✕
          </button>
        </div>
        <div className="pf-modal-body">
          {err && <div style={{ color: 'var(--s-critical)', fontSize: 13 }}>Could not load report: {err}</div>}
          {!md && !err && <div className="pf-empty">Loading report…</div>}
          {md && renderMarkdown(md)}
        </div>
      </div>
    </div>
  );
}

function TrendChart({ points }: { points: { t: number; passRate: number }[] }) {
  const option = useMemo<EChartsOption>(() => {
    const green = token('--c-green');
    const ink3 = token('--ink-3');
    return {
      grid: { left: 44, right: 20, top: 16, bottom: 26 },
      tooltip: {
        trigger: 'axis',
        formatter: (raw: unknown) => {
          const p = (raw as { value: [number, number] }[])[0];
          return `${formatDate(p.value[0])} ${formatClock(p.value[0])}<br/>pass-rate: ${p.value[1].toFixed(0)}%`;
        },
      },
      xAxis: {
        type: 'time',
        axisLabel: { color: ink3, fontSize: 10, formatter: (v: number) => formatDate(v) },
      },
      yAxis: {
        type: 'value',
        min: 0,
        max: 100,
        name: 'pass-rate %',
        nameTextStyle: { color: ink3, fontSize: 10, align: 'left' },
        axisLabel: { color: ink3, fontSize: 10 },
      },
      series: [
        {
          type: 'line',
          data: points.map((p) => [p.t, p.passRate]),
          showSymbol: true,
          symbolSize: 6,
          lineStyle: { color: green, width: 2 },
          itemStyle: { color: green },
          areaStyle: { color: token('--sage-soft'), opacity: 1 },
        },
      ],
    };
  }, [points]);
  return <EChart option={option} style={{ height: 160 }} />;
}

export function HistoryCard() {
  const { data: reports } = usePoll<QAReportEntry[]>(() => fetchReports(), 8000);
  const [summaries, setSummaries] = useState<Record<string, ReportSummary | null>>({});
  const [open, setOpen] = useState<string | null>(null);

  const list = reports ?? [];
  const namesKey = list.map((r) => r.name).join('|');

  // Fetch + parse each report's markdown once (for the trend). Only new names.
  useEffect(() => {
    if (list.length === 0) return;
    let cancelled = false;
    const missing = list.filter((r) => !(r.name in summaries));
    if (missing.length === 0) return;
    Promise.all(
      missing.map(async (r) => {
        try {
          const md = await fetchReportMarkdown(r.name);
          return [r.name, parseReportSummary(md)] as const;
        } catch {
          return [r.name, null] as const;
        }
      })
    ).then((pairs) => {
      if (cancelled) return;
      setSummaries((prev) => {
        const next = { ...prev };
        for (const [name, sum] of pairs) next[name] = sum;
        return next;
      });
    });
    return () => {
      cancelled = true;
    };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [namesKey]);

  const trendPoints = useMemo(() => {
    const pts: { t: number; passRate: number }[] = [];
    for (const r of list) {
      const s = summaries[r.name];
      if (!s) continue;
      const total = s.pass + s.degraded + s.fail + s.blind + s.inconclusive;
      if (total === 0) continue;
      const t = s.startedAt ? new Date(s.startedAt).getTime() : new Date(r.mtime).getTime();
      pts.push({ t, passRate: (s.pass / total) * 100 });
    }
    return pts.sort((a, b) => a.t - b.t);
  }, [list, summaries]);

  const parsedCount = list.filter((r) => summaries[r.name]).length;
  const allFetched = list.every((r) => r.name in summaries);

  return (
    <div className="pf-card">
      <div className="pf-card-head">
        <h2 className="card-title">Campaign history</h2>
        <span className="pf-head-meta">{list.length} report{list.length === 1 ? '' : 's'}</span>
      </div>

      {list.length === 0 ? (
        <div className="pf-empty">No saved reports yet. A campaign writes one to logs/qa/ on finish.</div>
      ) : (
        <>
          {trendPoints.length >= 3 ? (
            <TrendChart points={trendPoints} />
          ) : (
            <div className="pf-provenance" style={{ marginBottom: 8 }}>
              {list.length < 3
                ? `Pass-rate trend appears after 3 campaigns (${list.length} so far).`
                : allFetched && parsedCount < 3
                  ? 'Reports lack a parseable summary line — trend hidden.'
                  : 'Loading campaign summaries…'}
            </div>
          )}

          <div className="pf-report-list">
            {list.map((r) => {
              const s = summaries[r.name];
              return (
                <div key={r.name} className="pf-report-row" onClick={() => setOpen(r.name)}>
                  <span className="pf-report-name">{reportLabel(r.name, r.mtime)}</span>
                  <span className="pf-report-meta">
                    {s ? `${s.pass}✓ ${s.fail}✕ ${s.blind}⚠ · ` : ''}
                    {prettyBytes(r.bytes)}
                  </span>
                </div>
              );
            })}
          </div>
        </>
      )}

      {open && <ReportModal name={open} onClose={() => setOpen(null)} />}
    </div>
  );
}
