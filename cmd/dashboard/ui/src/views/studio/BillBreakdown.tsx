// Bill breakdown (DESIGN_BRIEF.md §4.3): one horizontal stacked bar per policy,
// line-item kinds as segments, export credit rendered left of zero, 2px gaps,
// shared category colors + a table toggle (the accessible relief). Credits-
// banked chip when the focus tariff's LEXA run carried NEM credit forward.

import { useMemo, useState } from 'react';
import type { EChartsOption } from 'echarts';
import { EChart } from '../../lib/echart';
import { token } from '../../lib/colors';
import { formatDollars } from '../../lib/format';
import { CreditsBankedChip } from './badges';
import type { WhatifResponse, LineItem, Policy } from './types';
import { runFor, POLICY_ORDER, POLICY_LABEL } from './types';

// Bill-kind → color. This chart carries no power/policy entities, so a
// categorical-by-kind mapping is legitimate; export credit is deliberately green
// (a credit / the win), matching the diverging export pole.
const KIND_COLOR: Record<string, string> = {
  fixed: '--c-indigo',
  energy: '--c-amber',
  tier_adder: '--c-red',
  riders: '--c-teal',
  demand: '--c-blue',
  export_credit: '--c-green',
};
const KIND_LABEL: Record<string, string> = {
  fixed: 'Fixed',
  energy: 'Energy',
  tier_adder: 'Tier adder',
  riders: 'Delivery & riders',
  demand: 'Demand',
  export_credit: 'Export credit',
};
const KIND_ORDER = ['fixed', 'energy', 'tier_adder', 'riders', 'demand', 'export_credit'];

interface Seg {
  key: string;
  kind: string;
  label: string;
}

function aggregate(items: LineItem[]): Map<string, number> {
  const m = new Map<string, number>();
  for (const it of items) {
    const key = `${it.kind}::${it.label}`;
    m.set(key, (m.get(key) ?? 0) + it.amount_usd);
  }
  return m;
}

export function BillBreakdown({
  response,
  focusTariffId,
}: {
  response: WhatifResponse;
  focusTariffId: string;
}) {
  const [showTable, setShowTable] = useState(false);

  const model = useMemo(() => {
    const perPolicy = new Map<Policy, Map<string, number>>();
    const runByPolicy = new Map<Policy, ReturnType<typeof runFor>>();
    for (const p of POLICY_ORDER) {
      const run = runFor(response.runs, focusTariffId, p);
      runByPolicy.set(p, run);
      perPolicy.set(p, run ? aggregate(run.bill.line_items) : new Map());
    }

    // Union of segments, ordered by kind then first appearance.
    const segMap = new Map<string, Seg>();
    for (const p of POLICY_ORDER) {
      const run = runByPolicy.get(p);
      if (!run) continue;
      for (const it of run.bill.line_items) {
        const key = `${it.kind}::${it.label}`;
        if (!segMap.has(key)) segMap.set(key, { key, kind: it.kind, label: it.label });
      }
    }
    const segs = [...segMap.values()].sort((a, b) => {
      const ka = KIND_ORDER.indexOf(a.kind);
      const kb = KIND_ORDER.indexOf(b.kind);
      return ka - kb;
    });

    const kindsPresent = KIND_ORDER.filter((k) => segs.some((s) => s.kind === k));
    const totals = POLICY_ORDER.map((p) => runByPolicy.get(p)?.bill.total_usd ?? 0);
    const lexaRun = runByPolicy.get('der_lexa');
    const dumbRun = runByPolicy.get('der_dumb');
    const carryover =
      (lexaRun?.bill.credit_carryover_usd ?? 0) || (dumbRun?.bill.credit_carryover_usd ?? 0);

    return { perPolicy, segs, kindsPresent, totals, carryover };
  }, [response, focusTariffId]);

  const option = useMemo<EChartsOption>(() => {
    const cats = POLICY_ORDER.map((p) => POLICY_LABEL[p]);
    const series = model.segs.map((seg) => ({
      name: seg.label,
      type: 'bar' as const,
      stack: 'bill',
      barWidth: 30,
      itemStyle: {
        color: token(KIND_COLOR[seg.kind] ?? '--c-blue'),
        borderColor: '#fff',
        borderWidth: 1.5,
        borderRadius: 2,
      },
      data: POLICY_ORDER.map((p) => {
        const v = model.perPolicy.get(p)?.get(seg.key);
        return v === undefined ? 0 : Number(v.toFixed(2));
      }),
    }));

    return {
      grid: { left: 96, right: 24, top: 10, bottom: 34 },
      tooltip: {
        trigger: 'axis',
        axisPointer: { type: 'shadow' },
        formatter: (params: unknown) => {
          const arr = params as Array<{ seriesName: string; value: number; color: string; axisValue: string; dataIndex: number }>;
          if (!arr.length) return '';
          let html = `<div style="font-weight:600">${arr[0].axisValue}</div>`;
          for (const p of arr) {
            if (!p.value) continue;
            html += `<div><span style="display:inline-block;width:8px;height:8px;border-radius:2px;background:${p.color};margin-right:6px"></span>${p.seriesName}: <b>${formatDollars(p.value)}</b></div>`;
          }
          html += `<div style="margin-top:3px;border-top:1px solid #eee;padding-top:3px">Total: <b>${formatDollars(model.totals[arr[0].dataIndex])}</b></div>`;
          return html;
        },
      },
      xAxis: {
        type: 'value',
        axisLabel: { color: token('--ink-3'), fontSize: 11, formatter: (v: number) => formatDollars(v) },
        splitLine: { lineStyle: { color: token('--line') } },
        axisLine: { show: false },
      },
      yAxis: {
        type: 'category',
        inverse: true,
        data: cats,
        axisLabel: { color: token('--ink-2'), fontSize: 12 },
        axisLine: { lineStyle: { color: token('--line') } },
      },
      series,
    };
  }, [model]);

  return (
    <div className="st-card">
      <div className="st-card-head">
        <h2 className="card-title">Bill breakdown</h2>
        <div style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
          {model.carryover > 0 ? <CreditsBankedChip usd={model.carryover} /> : null}
          <button
            className={`st-btn-ghost${showTable ? ' on' : ''}`}
            onClick={() => setShowTable((s) => !s)}
          >
            {showTable ? 'Chart' : 'Table'}
          </button>
        </div>
      </div>

      {showTable ? (
        <div className="st-table-wrap">
          <table className="st-table">
            <thead>
              <tr>
                <th>Line item</th>
                {POLICY_ORDER.map((p) => (
                  <th key={p}>{POLICY_LABEL[p]}</th>
                ))}
              </tr>
            </thead>
            <tbody>
              {model.segs.map((seg) => (
                <tr key={seg.key}>
                  <td>
                    <span
                      className="st-legend-swatch"
                      style={{
                        display: 'inline-block',
                        marginRight: 7,
                        background: token(KIND_COLOR[seg.kind] ?? '--c-blue'),
                      }}
                    />
                    {seg.label}
                  </td>
                  {POLICY_ORDER.map((p) => {
                    const v = model.perPolicy.get(p)?.get(seg.key);
                    return (
                      <td key={p} className="muted">
                        {v === undefined ? '—' : formatDollars(v)}
                      </td>
                    );
                  })}
                </tr>
              ))}
              <tr className="total-row">
                <td>Total</td>
                {model.totals.map((t, i) => (
                  <td key={i}>{formatDollars(t)}</td>
                ))}
              </tr>
            </tbody>
          </table>
        </div>
      ) : (
        <>
          <EChart option={option} style={{ height: 170 }} />
          <div className="st-legend">
            {model.kindsPresent.map((k) => (
              <span key={k} className="st-legend-item">
                <span
                  className="st-legend-swatch"
                  style={{ background: token(KIND_COLOR[k] ?? '--c-blue') }}
                />
                {KIND_LABEL[k] ?? k}
              </span>
            ))}
          </div>
        </>
      )}
    </div>
  );
}
