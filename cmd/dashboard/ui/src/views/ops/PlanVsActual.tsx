import { useEffect, useMemo, useRef, useState } from 'react';
import type { EChartsOption } from 'echarts';
import { EChart } from '../../lib/echart';
import { getJSON } from '../../lib/api';
import { usePoll } from '../../lib/usePoll';
import { POWER_COLORS, token } from '../../lib/colors';
import { formatWatts, formatDollars, formatDuration } from '../../lib/format';
import type { HubPlan, HubStatus } from './types';
import { pushCapped, toMs } from './util';

// Plan vs actual (brief §4.3): the hub's 24 h forecast (dashed, entity colors)
// against the live measured trail (solid). One y-axis (power). Plan polled at
// 30 s; the measured trail is fed by the parent's 1 s status poll and bounded
// to ~2 h.

const TRAIL_CAP = 7200; // 2 h @ 1 s

interface TrailPoint { ms: number; solar: number; battery: number; grid: number; }

const S = POWER_COLORS;

export function PlanVsActual({ status }: { status?: HubStatus }) {
  const { data: plan } = usePoll<HubPlan>(() => getJSON<HubPlan>('/api/hub/plan'), 30000);
  const [trail, setTrail] = useState<TrailPoint[]>([]);
  const lastTs = useRef<string>('');

  useEffect(() => {
    const ts = status?.timestamp;
    if (!ts || ts === lastTs.current || !status?.power) return;
    lastTs.current = ts;
    const p = status.power;
    setTrail((prev) => pushCapped(prev, { ms: toMs(ts), solar: p.solar_W, battery: p.battery_W, grid: p.grid_W }, TRAIL_CAP));
  }, [status]);

  const option = useMemo<EChartsOption>(() => {
    const ink = token('--ink');
    const ink3 = token('--ink-3');
    const line = token('--line');

    const planSeries = (name: string, color: string, pts: [number, number][]) => ({
      name,
      type: 'line' as const,
      showSymbol: false,
      lineStyle: { color, width: 2, type: 'dashed' as const },
      itemStyle: { color },
      data: pts,
      sampling: 'lttb' as const,
      z: 2,
    });
    const actualSeries = (name: string, color: string, pick: (t: TrailPoint) => number) => ({
      name,
      type: 'line' as const,
      showSymbol: false,
      lineStyle: { color, width: 2 },
      itemStyle: { color },
      data: trail.map((t) => [t.ms, pick(t)] as [number, number]),
      sampling: 'lttb' as const,
      z: 3,
    });

    const solarPlan: [number, number][] = plan?.solar_forecast?.map((p) => [toMs(p.t), p.solar_W]) ?? [];
    const battPlan: [number, number][] = plan?.battery_plan?.map((p) => [toMs(p.t), p.setpoint_W]) ?? [];
    const gridPlan: [number, number][] = plan?.cost_plan?.map((p) => [toMs(p.t), p.grid_W]) ?? [];
    const nowMs = Date.now();

    return {
      color: [S.solar, S.battery, S.grid],
      grid: { left: 52, right: 16, top: 40, bottom: 28 },
      legend: {
        top: 0,
        left: 0,
        itemWidth: 18,
        itemHeight: 10,
        textStyle: { color: token('--ink-2'), fontSize: 11 },
        data: ['Solar · plan', 'Solar · actual', 'Battery · plan', 'Battery · actual', 'Grid · plan', 'Grid · actual'],
      },
      tooltip: {
        trigger: 'axis',
        axisPointer: { type: 'cross', lineStyle: { color: ink3, type: 'dashed' } },
        valueFormatter: (v) => (typeof v === 'number' ? formatWatts(v) : '—'),
      },
      xAxis: {
        type: 'time',
        axisLabel: { color: ink3, fontSize: 11, hideOverlap: true },
      },
      yAxis: {
        type: 'value',
        name: 'kW',
        nameTextStyle: { color: ink3, fontSize: 11, align: 'right' },
        axisLabel: { color: ink3, fontSize: 11, formatter: (v: number) => (v / 1000).toFixed(Math.abs(v) >= 10000 ? 0 : 1) },
        splitLine: { lineStyle: { color: line } },
        axisLine: { show: false },
      },
      textStyle: { color: ink },
      series: [
        { ...planSeries('Solar · plan', S.solar, solarPlan),
          markLine: {
            silent: true, symbol: 'none',
            data: [{ xAxis: nowMs }],
            lineStyle: { color: ink3, type: 'dotted', width: 1 },
            label: { formatter: 'now', color: ink3, fontSize: 10, position: 'insideEndTop' },
          },
        },
        actualSeries('Solar · actual', S.solar, (t) => t.solar),
        planSeries('Battery · plan', S.battery, battPlan),
        actualSeries('Battery · actual', S.battery, (t) => t.battery),
        planSeries('Grid · plan', S.grid, gridPlan),
        actualSeries('Grid · actual', S.grid, (t) => t.grid),
      ],
    };
  }, [plan, trail]);

  const hasAny = (plan?.solar_forecast?.length ?? 0) > 0 || trail.length > 0;
  const genAgeS = plan ? (Date.now() - new Date(plan.generated_at).getTime()) / 1000 : NaN;

  return (
    <div className="ops-card">
      <div className="ops-card-head">
        <h2 className="card-title">Plan vs Actual</h2>
        <div className="ops-head-meta">dashed = plan · solid = measured</div>
      </div>
      {!hasAny ? (
        <p className="ops-empty">No plan yet — the chart draws once the hub publishes a forecast and the measured trail begins to fill.</p>
      ) : (
        <EChart option={option} style={{ height: 288 }} streaming />
      )}
      <div className="ops-stat-row">
        <div>
          <div className="ops-stat-label">Plan cost</div>
          <div className="ops-stat-val accent">{plan ? formatDollars(plan.total_cost) : '—'}</div>
        </div>
        <div>
          <div className="ops-stat-label">Generated</div>
          <div className="ops-stat-val">{Number.isFinite(genAgeS) ? `${formatDuration(genAgeS)} ago` : '—'}</div>
        </div>
        <div>
          <div className="ops-stat-label">Horizon</div>
          <div className="ops-stat-val">{plan ? `${plan.horizon_h} h · ${plan.slot_minutes}-min` : '—'}</div>
        </div>
      </div>
    </div>
  );
}
