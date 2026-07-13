// Day detail (DESIGN_BRIEF.md §4.5): stacked area of load/pv/batt/ev in entity
// colors + grid line overlay + a rate band strip underneath, for the engine's
// costliest-day tick trace. Policy tabs share the same date.
//
// Sign handling: the four component areas are plotted as +load +ev −pv −batt,
// so their algebraic sum equals grid_kw — the overlaid grid line traces the net.
// Demand pushes up, generation/discharge pulls down. Tooltip reports each
// entity's true magnitude (not the plotted sign).

import { useMemo, useState } from 'react';
import type { EChartsOption } from 'echarts';
import { EChart } from '../../lib/echart';
import { POWER_COLORS, SEQUENTIAL_RAMP, token } from '../../lib/colors';
import { formatKW, formatPercent, formatDate } from '../../lib/format';
import type { WhatifResponse, Policy, DayDetail as DayDetailData } from './types';
import { runFor, POLICY_ORDER, POLICY_LABEL } from './types';

function tickLabel(i: number): string {
  const m = i * 15;
  return `${String(Math.floor(m / 60)).padStart(2, '0')}:${String(m % 60).padStart(2, '0')}`;
}

export function DayDetail({
  response,
  focusTariffId,
}: {
  response: WhatifResponse;
  focusTariffId: string;
}) {
  const [policy, setPolicy] = useState<Policy>('der_lexa');
  const run = runFor(response.runs, focusTariffId, policy);
  const dd: DayDetailData | undefined = run?.day_detail;

  const option = useMemo<EChartsOption | null>(() => {
    if (!dd) return null;
    const n = dd.ticks;
    const cats = Array.from({ length: n }, (_, i) => tickLabel(i));
    const rateData = dd.rate_usd_per_kwh.map((r, i) => [i, 0, Number(r.toFixed(5))]);
    const rateMin = Math.min(...dd.rate_usd_per_kwh);
    const rateMax = Math.max(...dd.rate_usd_per_kwh);

    const area = (name: string, color: string, data: number[]) => ({
      name,
      type: 'line' as const,
      stack: 'net',
      xAxisIndex: 0,
      yAxisIndex: 0,
      data,
      showSymbol: false,
      lineStyle: { width: 1, color, opacity: 0.7 },
      areaStyle: { color, opacity: 0.45 },
      itemStyle: { color },
    });

    return {
      color: [
        POWER_COLORS.home,
        POWER_COLORS.solar,
        POWER_COLORS.battery,
        POWER_COLORS.ev,
        POWER_COLORS.grid,
      ],
      legend: {
        top: 0,
        left: 0,
        itemWidth: 16,
        itemHeight: 9,
        textStyle: { color: token('--ink-2'), fontSize: 11 },
        data: ['Home load', 'Solar', 'Battery', 'EV', 'Grid (net)'],
      },
      axisPointer: { link: [{ xAxisIndex: 'all' }] },
      tooltip: {
        trigger: 'axis',
        axisPointer: { type: 'line', lineStyle: { color: token('--ink-3'), type: 'dashed' } },
        formatter: (params: unknown) => {
          const arr = params as Array<{ dataIndex: number }>;
          if (!arr.length) return '';
          const i = arr[0].dataIndex;
          const dot = (c: string) =>
            `<span style="display:inline-block;width:8px;height:8px;border-radius:50%;background:${c};margin-right:6px"></span>`;
          const batt = dd.batt_kw[i];
          const grid = dd.grid_kw[i];
          return (
            `<div style="font-weight:600">${formatDate(dd.date)} · ${tickLabel(i)}</div>` +
            `${dot(POWER_COLORS.home)}Home load: <b>${formatKW(dd.load_kw[i])}</b><br/>` +
            `${dot(POWER_COLORS.solar)}Solar: <b>${formatKW(dd.pv_kw[i])}</b><br/>` +
            `${dot(POWER_COLORS.battery)}Battery: <b>${formatKW(Math.abs(batt))}</b> ${batt >= 0 ? 'discharge' : 'charge'}<br/>` +
            `${dot(POWER_COLORS.ev)}EV: <b>${formatKW(dd.ev_kw[i])}</b><br/>` +
            `${dot(POWER_COLORS.grid)}Grid: <b>${formatKW(Math.abs(grid))}</b> ${grid >= 0 ? 'import' : 'export'}<br/>` +
            `<div style="margin-top:3px;border-top:1px solid #eee;padding-top:3px">SOC ${formatPercent(dd.soc_pct[i], 0)} · ${(dd.rate_usd_per_kwh[i] * 100).toFixed(2)}¢/kWh</div>`
          );
        },
      },
      grid: [
        { left: 54, right: 14, top: 30, height: 196 },
        { left: 54, right: 14, top: 238, height: 22 },
      ],
      xAxis: [
        {
          type: 'category',
          gridIndex: 0,
          data: cats,
          // boundaryGap true so this axis aligns cell-for-cell with the rate
          // strip below (a heatmap axis must be boundaryGap:true in echarts).
          boundaryGap: true,
          axisLabel: { show: false },
          axisLine: { lineStyle: { color: token('--line') } },
          axisTick: { show: false },
        },
        {
          type: 'category',
          gridIndex: 1,
          data: cats,
          boundaryGap: true,
          axisLabel: {
            color: token('--ink-3'),
            fontSize: 10,
            interval: (idx: number) => idx % 8 === 0,
          },
          axisLine: { lineStyle: { color: token('--line') } },
          axisTick: { show: false },
        },
      ],
      yAxis: [
        {
          type: 'value',
          gridIndex: 0,
          name: 'kW  (demand ↑ · supply ↓)',
          nameTextStyle: { color: token('--ink-3'), fontSize: 10, align: 'left' },
          axisLabel: { color: token('--ink-3'), fontSize: 11 },
          splitLine: { lineStyle: { color: token('--line') } },
          axisLine: { show: false },
        },
        {
          type: 'category',
          gridIndex: 1,
          data: ['rate'],
          boundaryGap: true,
          axisLabel: { show: false },
          axisLine: { show: false },
          axisTick: { show: false },
        },
      ],
      visualMap: {
        type: 'continuous',
        min: rateMin,
        max: rateMax === rateMin ? rateMin + 1e-6 : rateMax,
        seriesIndex: 5,
        dimension: 2,
        inRange: { color: SEQUENTIAL_RAMP },
        show: false,
      },
      series: [
        area('Home load', POWER_COLORS.home, dd.load_kw),
        area('Solar', POWER_COLORS.solar, dd.pv_kw.map((v) => -v)),
        area('Battery', POWER_COLORS.battery, dd.batt_kw.map((v) => -v)),
        area('EV', POWER_COLORS.ev, dd.ev_kw),
        {
          name: 'Grid (net)',
          type: 'line',
          xAxisIndex: 0,
          yAxisIndex: 0,
          data: dd.grid_kw,
          showSymbol: false,
          lineStyle: { color: POWER_COLORS.grid, width: 2 },
          itemStyle: { color: POWER_COLORS.grid },
          z: 6,
        },
        {
          name: '__rate',
          type: 'heatmap',
          xAxisIndex: 1,
          yAxisIndex: 1,
          data: rateData,
          itemStyle: { borderColor: '#fff', borderWidth: 0.4 },
        },
      ],
    };
  }, [dd]);

  return (
    <div className="st-card">
      <div className="st-card-head">
        <div>
          <h2 className="card-title">Day detail</h2>
          <div className="st-head-meta" style={{ marginTop: 4 }}>
            {dd ? `${formatDate(dd.date)} — the costliest day · demand ↑ · generation & discharge ↓ · strip = TOU rate` : ''}
          </div>
        </div>
        <div className="st-tabs">
          {POLICY_ORDER.map((p) => (
            <button
              key={p}
              className={`st-tab${p === policy ? ' active' : ''}`}
              onClick={() => setPolicy(p)}
            >
              {POLICY_LABEL[p]}
            </button>
          ))}
        </div>
      </div>
      {option ? (
        <EChart option={option} style={{ height: 288 }} notMerge />
      ) : (
        <p className="empty-state">No tick detail for this plan.</p>
      )}
    </div>
  );
}
