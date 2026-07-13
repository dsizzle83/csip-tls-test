// Live scenario timeline (brief §4.3, the flagship chart). From status.live[]:
// real meter W (solid blue) vs hub-believed W (dashed gray). Where they diverge
// past DIVERGE_W the gap between the lines is shaded --s-serious @ 18% — that
// shaded band IS the blindness visual (the hub acting on a reading reality has
// left behind). CannotComply ticks, hub-adopt transitions, and the adopted cap
// hairline annotate it. One y-axis (W). Side rail = newest decisions[]; below,
// SOC + EV sparkrows off the same samples.

import { useMemo } from 'react';
import type { EChartsOption } from 'echarts';
import { EChart } from '../../lib/echart';
import { token } from '../../lib/colors';
import { formatWatts } from '../../lib/format';
import type { MaySample } from './types';

const DIVERGE_W = 400; // gap wider than this = the hub is meaningfully blind
const MAX_POINTS = 240; // defensive client cap (backend already keeps ~120)

interface Params {
  seriesName?: string;
  value?: [number, number] | number;
  axisValueLabel?: string;
}

// ECharts label callbacks are typed loosely (CallbackDataParams); read the
// [t, W] tuple defensively and format the W component.
function endLabelText(p: unknown): string {
  const v = (p as Params).value;
  return Array.isArray(v) ? formatWatts(v[1]) : '';
}

function buildMainOption(samples: MaySample[]): EChartsOption {
  const blue = token('--c-blue');
  const gray = token('--ink-2');
  const serious = token('--s-serious');
  const ink3 = token('--ink-3');

  const real: [number, number][] = [];
  const hub: [number, number][] = [];
  const base: [number, number][] = []; // min(real,hub) — invisible stack floor
  const gap: [number, number][] = []; // divergence height (0 when within DIVERGE_W)
  const cannot: [number, number][] = [];

  for (const s of samples) {
    real.push([s.t, s.real_grid_W]);
    hub.push([s.t, s.hub_grid_W]);
    const lo = Math.min(s.real_grid_W, s.hub_grid_W);
    const diff = Math.abs(s.real_grid_W - s.hub_grid_W);
    base.push([s.t, lo]);
    gap.push([s.t, diff > DIVERGE_W ? diff : 0]);
    if (s.cannot_comply) cannot.push([s.t, s.real_grid_W]);
  }

  // hub-adopt transitions → vertical hairlines with a label chip.
  const adoptMarks: { xAxis: number; label: string }[] = [];
  for (let i = 1; i < samples.length; i++) {
    if (samples[i].hub_adopted !== samples[i - 1].hub_adopted) {
      adoptMarks.push({
        xAxis: samples[i].t,
        label: samples[i].hub_adopted ? `adopt ${samples[i].adopted_typ || 'control'}` : 'release',
      });
    }
  }

  // adopted cap → horizontal dashed hairline (only export/import map onto grid W).
  const lastAdopted = [...samples].reverse().find((s) => s.hub_adopted && s.adopted_lim_W > 0);
  let capLine: { yAxis: number; label: string } | null = null;
  if (lastAdopted) {
    const typ = lastAdopted.adopted_typ;
    if (typ === 'exportCap') capLine = { yAxis: -lastAdopted.adopted_lim_W, label: `export cap ${formatWatts(lastAdopted.adopted_lim_W)}` };
    else if (typ === 'importCap') capLine = { yAxis: lastAdopted.adopted_lim_W, label: `import cap ${formatWatts(lastAdopted.adopted_lim_W)}` };
  }

  return {
    grid: { left: 54, right: 66, top: 30, bottom: 34 },
    legend: {
      data: ['Real meter', 'Hub-believed'],
      top: 0,
      right: 0,
      icon: 'roundRect',
      itemWidth: 14,
      itemHeight: 3,
      textStyle: { color: token('--ink-2'), fontSize: 11 },
    },
    tooltip: {
      trigger: 'axis',
      axisPointer: { type: 'cross', lineStyle: { color: ink3 } },
      formatter: (raw: unknown) => {
        const params = raw as Params[];
        if (!params.length) return '';
        const t = Array.isArray(params[0].value) ? params[0].value[0] : params[0].axisValueLabel;
        const rows: Record<string, number> = {};
        for (const p of params) {
          if ((p.seriesName === 'Real meter' || p.seriesName === 'Hub-believed') && Array.isArray(p.value)) {
            rows[p.seriesName] = p.value[1];
          }
        }
        const r = rows['Real meter'];
        const h = rows['Hub-believed'];
        let out = `<b>t = ${Number(t).toFixed(0)} s</b>`;
        if (r != null) out += `<br/>Real meter: ${formatWatts(r)}`;
        if (h != null) out += `<br/>Hub-believed: ${formatWatts(h)}`;
        if (r != null && h != null) {
          const d = Math.abs(r - h);
          out += `<br/><span style="color:${d > DIVERGE_W ? serious : ink3}">divergence: ${formatWatts(d)}${d > DIVERGE_W ? ' ⚠' : ''}</span>`;
        }
        return out;
      },
    },
    xAxis: {
      type: 'value',
      name: 's',
      nameLocation: 'end',
      nameTextStyle: { color: ink3, fontSize: 10 },
      min: samples.length ? samples[0].t : 0,
      max: samples.length ? samples[samples.length - 1].t : 1,
      axisLabel: { color: ink3, fontSize: 11, formatter: (v: number) => `${Math.round(v)}` },
    },
    yAxis: {
      type: 'value',
      name: 'grid W',
      nameTextStyle: { color: ink3, fontSize: 10, align: 'right' },
      axisLabel: {
        color: ink3,
        fontSize: 11,
        formatter: (v: number) => (Math.abs(v) >= 1000 ? `${(v / 1000).toFixed(1)}k` : `${v}`),
      },
    },
    series: [
      // divergence band (stacked: invisible base + shaded gap between the lines)
      {
        name: '__base',
        type: 'line',
        stack: 'band',
        data: base,
        symbol: 'none',
        lineStyle: { opacity: 0 },
        areaStyle: { opacity: 0 },
        silent: true,
        z: 1,
      },
      {
        name: '__gap',
        type: 'line',
        stack: 'band',
        data: gap,
        symbol: 'none',
        lineStyle: { opacity: 0 },
        areaStyle: { color: serious, opacity: 0.18 },
        silent: true,
        z: 1,
      },
      {
        name: 'Real meter',
        type: 'line',
        data: real,
        showSymbol: false,
        smooth: false,
        lineStyle: { color: blue, width: 2 },
        itemStyle: { color: blue },
        z: 5,
        endLabel: { show: true, color: blue, fontSize: 11, formatter: (p: unknown) => endLabelText(p) },
        markLine: {
          silent: true,
          symbol: 'none',
          data: [
            ...(capLine
              ? [
                  {
                    yAxis: capLine.yAxis,
                    lineStyle: { color: gray, type: 'dashed' as const, width: 1 },
                    label: { formatter: capLine.label, color: token('--ink-2'), fontSize: 10, position: 'insideEndTop' as const },
                  },
                ]
              : []),
            ...adoptMarks.map((m) => ({
              xAxis: m.xAxis,
              lineStyle: { color: ink3, type: 'dashed' as const, width: 1 },
              label: { formatter: m.label, color: token('--ink-2'), fontSize: 10, rotate: 90, position: 'insideEndTop' as const },
            })),
          ],
        },
      },
      {
        name: 'Hub-believed',
        type: 'line',
        data: hub,
        showSymbol: false,
        smooth: false,
        lineStyle: { color: gray, width: 2, type: 'dashed' },
        itemStyle: { color: gray },
        z: 4,
        endLabel: { show: true, color: gray, fontSize: 11, formatter: (p: unknown) => endLabelText(p) },
      },
      // CannotComply ticks
      {
        name: 'CannotComply',
        type: 'scatter',
        data: cannot,
        symbol: 'triangle',
        symbolSize: 9,
        itemStyle: { color: serious },
        z: 6,
        tooltip: { show: false },
      },
    ],
    graphic: samples.length
      ? []
      : [{ type: 'text', left: 'center', top: 'middle', style: { text: 'no live samples', fill: ink3, fontSize: 13 } }],
  };
}

function sparkOption(
  samples: MaySample[],
  series: { name: string; color: string; dashed?: boolean; pick: (s: MaySample) => number }[],
  unit: 'pct' | 'W'
): EChartsOption {
  const ink3 = token('--ink-3');
  return {
    grid: { left: 40, right: 46, top: 8, bottom: 18 },
    legend: series.length > 1 ? { data: series.map((s) => s.name), top: 0, right: 0, itemWidth: 12, itemHeight: 3, textStyle: { color: token('--ink-2'), fontSize: 10 } } : undefined,
    tooltip: {
      trigger: 'axis',
      axisPointer: { type: 'line', lineStyle: { color: ink3 } },
      formatter: (raw: unknown) => {
        const params = raw as Params[];
        if (!params.length) return '';
        const t = Array.isArray(params[0].value) ? params[0].value[0] : 0;
        let out = `<b>t = ${Number(t).toFixed(0)} s</b>`;
        for (const p of params) {
          if (Array.isArray(p.value)) out += `<br/>${p.seriesName}: ${unit === 'pct' ? `${p.value[1].toFixed(0)}%` : formatWatts(p.value[1])}`;
        }
        return out;
      },
    },
    xAxis: {
      type: 'value',
      min: samples.length ? samples[0].t : 0,
      max: samples.length ? samples[samples.length - 1].t : 1,
      axisLabel: { color: ink3, fontSize: 10, formatter: (v: number) => `${Math.round(v)}` },
    },
    yAxis: {
      type: 'value',
      ...(unit === 'pct' ? { min: 0, max: 100 } : {}),
      axisLabel: { color: ink3, fontSize: 10, formatter: (v: number) => (unit === 'pct' ? `${v}` : Math.abs(v) >= 1000 ? `${(v / 1000).toFixed(1)}k` : `${v}`) },
    },
    series: series.map((s) => ({
      name: s.name,
      type: 'line',
      data: samples.map((smp) => [smp.t, s.pick(smp)]),
      showSymbol: false,
      lineStyle: { color: s.color, width: 2, type: s.dashed ? 'dashed' : 'solid' },
      itemStyle: { color: s.color },
    })),
  };
}

export function LiveTimeline({ samples }: { samples: MaySample[] }) {
  const capped = useMemo(() => (samples.length > MAX_POINTS ? samples.slice(samples.length - MAX_POINTS) : samples), [samples]);
  const mainOption = useMemo(() => buildMainOption(capped), [capped]);
  const socOption = useMemo(
    () =>
      sparkOption(
        capped,
        [
          { name: 'Battery SOC', color: token('--c-green'), pick: (s) => s.battery_sim_soc },
          { name: 'EV SOC', color: token('--c-teal'), pick: (s) => s.ev_soc },
        ],
        'pct'
      ),
    [capped]
  );
  const evOption = useMemo(
    () =>
      sparkOption(
        capped,
        [
          { name: 'EV draw (truth)', color: token('--c-teal'), pick: (s) => s.ev_sim_W },
          { name: 'EV draw (hub)', color: token('--ink-2'), dashed: true, pick: (s) => s.ev_W },
        ],
        'W'
      ),
    [capped]
  );

  const latest = capped.length ? capped[capped.length - 1] : undefined;
  const decisions = latest?.decisions ?? [];

  return (
    <div>
      <div className="pf-live-grid">
        <div>
          <EChart option={mainOption} style={{ height: 300 }} streaming notMerge />
        </div>
        <div className="pf-decisions">
          <div className="pf-decisions-title">Hub decisions · t={latest ? latest.t.toFixed(0) : '—'}s</div>
          {decisions.length === 0 && <div className="pf-empty" style={{ padding: 12 }}>No decisions in the newest sample.</div>}
          {decisions.map((d, i) => (
            <div key={i} className="pf-decision-row">
              {d}
            </div>
          ))}
        </div>
      </div>
      <div className="pf-spark-row">
        <div className="pf-spark">
          <div className="pf-spark-title">State of charge (%) — battery + EV</div>
          <EChart option={socOption} style={{ height: 120 }} streaming notMerge />
        </div>
        <div className="pf-spark">
          <div className="pf-spark-title">EV draw (W) — truth vs hub</div>
          <EChart option={evOption} style={{ height: 120 }} streaming notMerge />
        </div>
      </div>
    </div>
  );
}
