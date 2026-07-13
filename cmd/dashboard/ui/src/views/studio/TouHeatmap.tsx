// TOU price heatmap (DESIGN_BRIEF.md §4.4): x = day, y = hour, cell = import
// rate via the SEQUENTIAL amber ramp (never green for price). Rates computed
// client-side from the tariff periods (tariffRates.ts). Battery-discharge
// overlay is OMITTED, not faked — we only have tick granularity for one day, so
// a month-grid overlay would be invented. Small multiples, max 2.

import { useMemo } from 'react';
import type { EChartsOption } from 'echarts';
import { EChart } from '../../lib/echart';
import { SEQUENTIAL_RAMP, token } from '../../lib/colors';
import { formatDate } from '../../lib/format';
import { importRateAt } from './tariffRates';
import type { Tariff } from './types';

function cents(rate: number): string {
  return `${(rate * 100).toFixed(2)}¢/kWh`;
}

function Heatmap({ tariff, dates }: { tariff: Tariff; dates: string[] }) {
  const { option, flat, band } = useMemo(() => {
    const hours = Array.from({ length: 24 }, (_, h) => h);
    const data: Array<[number, number, number, string]> = [];
    let min = Infinity;
    let max = -Infinity;
    for (let x = 0; x < dates.length; x++) {
      for (const h of hours) {
        const cell = importRateAt(tariff, dates[x], h);
        const rate = cell ? cell.rate : 0;
        data.push([x, h, Number(rate.toFixed(5)), cell?.label ?? '—']);
        if (rate < min) min = rate;
        if (rate > max) max = rate;
      }
    }
    if (!Number.isFinite(min)) min = 0;
    if (!Number.isFinite(max)) max = 0;
    const isFlat = max - min < 1e-6;
    // visualMap needs min<max; for a flat plan, center the single rate mid-ramp.
    const vmMin = isFlat ? 0 : min;
    const vmMax = isFlat ? (max > 0 ? max * 2 : 1) : max;

    const opt: EChartsOption = {
      grid: { left: 40, right: 12, top: 12, bottom: 58 },
      tooltip: {
        position: 'top',
        formatter: (params: unknown) => {
          const p = params as { data: [number, number, number, string] };
          const [x, h, rate, label] = p.data;
          return `<div style="font-weight:600">${formatDate(dates[x])} · ${String(h).padStart(2, '0')}:00</div>${label} · <b>${cents(rate)}</b>`;
        },
      },
      xAxis: {
        type: 'category',
        boundaryGap: true, // required by echarts for a cartesian heatmap
        data: dates.map((d) => d.split('-')[2].replace(/^0/, '')),
        splitArea: { show: false },
        axisLabel: {
          color: token('--ink-3'),
          fontSize: 10,
          interval: (idx: number) => idx % 5 === 0,
        },
        axisLine: { lineStyle: { color: token('--line') } },
        axisTick: { show: false },
      },
      yAxis: {
        type: 'category',
        boundaryGap: true,
        data: hours.map(String),
        axisLabel: {
          color: token('--ink-3'),
          fontSize: 10,
          interval: (idx: number) => idx % 6 === 0,
          formatter: (v: string) => `${v}:00`,
        },
        axisLine: { lineStyle: { color: token('--line') } },
        axisTick: { show: false },
      },
      visualMap: {
        type: 'continuous',
        min: vmMin,
        max: vmMax,
        // Pin to the rate dimension — data rows carry a 4th element (the period
        // label for tooltips), else visualMap would color by that string.
        dimension: 2,
        calculable: true,
        orient: 'horizontal',
        left: 'center',
        bottom: 4,
        itemWidth: 12,
        itemHeight: 120,
        text: ['expensive', 'cheap'],
        textStyle: { color: token('--ink-3'), fontSize: 10 },
        inRange: { color: SEQUENTIAL_RAMP },
        formatter: (v: unknown) => cents(Number(v)),
      },
      series: [
        {
          type: 'heatmap',
          data,
          progressive: 0,
          itemStyle: { borderColor: '#fff', borderWidth: 0.5 },
          emphasis: { itemStyle: { borderColor: token('--ink'), borderWidth: 1 } },
        },
      ],
    };
    return { option: opt, flat: isFlat, band: { min, max } };
  }, [tariff, dates]);

  return (
    <div className="st-card">
      <div className="st-heat-title">{tariff.short_name || tariff.name}</div>
      <div className="st-heat-sub">
        {flat
          ? `Flat rate — ${cents(band.max)} all hours (computed from plan periods + riders)`
          : `Import rate ${cents(band.min)} – ${cents(band.max)} (computed from plan periods + riders)`}
      </div>
      <EChart option={option} style={{ height: 260 }} />
    </div>
  );
}

export function TouHeatmaps({ tariffs, dates }: { tariffs: Tariff[]; dates: string[] }) {
  const shown = tariffs.slice(0, 2);
  if (shown.length === 0 || dates.length === 0) return null;
  return (
    <div className="st-card">
      <div className="st-card-head">
        <h2 className="card-title">Time-of-use price map</h2>
        <div className="st-head-meta">
          x = day · y = hour · darker = pricier{tariffs.length > 2 ? ' · showing first 2 plans' : ''}
        </div>
      </div>
      <div className="st-heatmaps">
        {shown.map((t) => (
          <Heatmap key={t.id} tariff={t} dates={dates} />
        ))}
      </div>
    </div>
  );
}
