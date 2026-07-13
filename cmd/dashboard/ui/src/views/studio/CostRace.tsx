// Cumulative cost race (DESIGN_BRIEF.md §4.2): daily cumulative $ for the three
// policies (baseline gray, DER-only blue, LEXA green), direct end labels, and
// the baseline→LEXA gap filled sage-soft. One y-axis (cumulative $). Built from
// runs[].daily.cost_usd for the focus tariff.

import { useMemo } from 'react';
import type { EChartsOption } from 'echarts';
import { EChart } from '../../lib/echart';
import { POLICY_COLORS, token } from '../../lib/colors';
import { formatDollars, formatDate } from '../../lib/format';
import type { WhatifResponse } from './types';
import { runFor, POLICY_LABEL } from './types';

function cumulative(arr: number[]): number[] {
  let acc = 0;
  return arr.map((v) => (acc += v));
}

const HELPERS = new Set(['__band_lower', '__band_gap']);

export function CostRace({
  response,
  focusTariffId,
}: {
  response: WhatifResponse;
  focusTariffId: string;
}) {
  const option = useMemo<EChartsOption | null>(() => {
    const baseline = runFor(response.runs, focusTariffId, 'baseline');
    const dumb = runFor(response.runs, focusTariffId, 'der_dumb');
    const lexa = runFor(response.runs, focusTariffId, 'der_lexa');
    if (!baseline || !dumb || !lexa) return null;

    const dates = baseline.daily.dates;
    const baseCum = cumulative(baseline.daily.cost_usd);
    const dumbCum = cumulative(dumb.daily.cost_usd);
    const lexaCum = cumulative(lexa.daily.cost_usd);
    const gap = baseCum.map((b, i) => Math.max(0, b - lexaCum[i]));

    // showEnd: DER-only converges with LEXA on flat tariffs, so its end label
    // is suppressed (the legend still names it) to avoid label collision.
    const line = (name: string, color: string, data: number[], dashed = false, showEnd = true) => ({
      name,
      type: 'line' as const,
      data,
      showSymbol: false,
      smooth: false,
      lineStyle: { color, width: 2, type: dashed ? ('dashed' as const) : ('solid' as const) },
      itemStyle: { color },
      emphasis: { focus: 'series' as const },
      endLabel: {
        show: showEnd,
        formatter: () => name,
        color,
        fontSize: 11,
        fontWeight: 600 as const,
      },
      z: 5,
    });

    return {
      color: [POLICY_COLORS.baseline, POLICY_COLORS.derNoLexa, POLICY_COLORS.derLexa],
      grid: { left: 58, right: 128, top: 34, bottom: 28 },
      legend: {
        top: 0,
        left: 0,
        itemWidth: 18,
        itemHeight: 10,
        textStyle: { color: token('--ink-2'), fontSize: 12 },
        data: [POLICY_LABEL.baseline, POLICY_LABEL.der_dumb, POLICY_LABEL.der_lexa],
      },
      tooltip: {
        trigger: 'axis',
        axisPointer: { type: 'cross', lineStyle: { color: token('--ink-3'), type: 'dashed' } },
        formatter: (params: unknown) => {
          const arr = params as Array<{ seriesName: string; dataIndex: number; value: number; color: string }>;
          if (!arr.length) return '';
          const di = arr[0].dataIndex;
          let html = `<div style="font-weight:600">${formatDate(dates[di])} · cumulative</div>`;
          for (const p of arr) {
            if (HELPERS.has(p.seriesName)) continue;
            html += `<div><span style="display:inline-block;width:8px;height:8px;border-radius:50%;background:${p.color};margin-right:6px"></span>${p.seriesName}: <b>${formatDollars(p.value)}</b></div>`;
          }
          return html;
        },
      },
      xAxis: {
        type: 'category',
        data: dates,
        boundaryGap: false,
        axisLabel: {
          color: token('--ink-3'),
          fontSize: 11,
          hideOverlap: true,
          formatter: (v: string) => formatDate(v),
        },
      },
      yAxis: {
        type: 'value',
        axisLabel: {
          color: token('--ink-3'),
          fontSize: 11,
          formatter: (v: number) => formatDollars(v),
        },
        splitLine: { lineStyle: { color: token('--line') } },
        axisLine: { show: false },
      },
      series: [
        // Sage band between LEXA (lower) and baseline (upper) via a 2-series stack.
        {
          name: '__band_lower',
          type: 'line',
          stack: 'band',
          data: lexaCum,
          showSymbol: false,
          lineStyle: { opacity: 0 },
          areaStyle: { opacity: 0 },
          silent: true,
          z: 1,
        },
        {
          name: '__band_gap',
          type: 'line',
          stack: 'band',
          data: gap,
          showSymbol: false,
          lineStyle: { opacity: 0 },
          areaStyle: { color: token('--sage-soft'), opacity: 1 },
          silent: true,
          z: 1,
        },
        line(POLICY_LABEL.baseline, POLICY_COLORS.baseline, baseCum),
        line(POLICY_LABEL.der_dumb, POLICY_COLORS.derNoLexa, dumbCum, true, false),
        line(POLICY_LABEL.der_lexa, POLICY_COLORS.derLexa, lexaCum),
      ],
    };
  }, [response, focusTariffId]);

  if (!option) return null;
  return <EChart option={option} style={{ height: 300 }} />;
}
