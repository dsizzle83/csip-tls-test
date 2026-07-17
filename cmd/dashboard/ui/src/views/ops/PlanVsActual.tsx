import { useEffect, useMemo, useRef, useState } from 'react';
import type {
  EChartsOption,
  CustomSeriesRenderItem,
  MarkAreaComponentOption,
  MarkLineComponentOption,
  MarkPointComponentOption,
} from 'echarts';
import { EChart } from '../../lib/echart';
import { getJSON } from '../../lib/api';
import { usePoll } from '../../lib/usePoll';
import { POWER_COLORS, SEQUENTIAL_RAMP, token } from '../../lib/colors';
import { formatWatts, formatDollars, formatDuration, formatPercent } from '../../lib/format';
import type { HubPlan, HubStatus } from './types';
import { evPowerW, pushCapped, toMs } from './util';

// Plan vs Actual (brief §4.3, rebuilt) — the demo centerpiece. A single 24 h
// timeline that shows EVERY signal the optimizer reasons over, ported from the
// Savings Studio DayDetail (studio/DayDetail.tsx): a stacked-area energy
// landscape (Home ↑ demand · Solar/Battery/EV ↓ supply, sign per DayDetail) with
// the net-grid line threading the stack top (import above zero / export below),
// plus a battery-SOC lane and a TOU price heatmap strip beneath it. One y-axis
// PER lane (brief §2 forbids dual-axis) — power(kW) / SOC(%) / price($/kWh) each
// get their own grid rather than a secondary axis.
//
// PLAN is the hub's forecast (dashed lines + translucent area); ACTUAL is the
// live measured trail (solid lines), fed by the parent's 1 s status poll and
// bounded to ~2 h (brief §2). The optimizer's rationale is made traceable two
// ways: (a) markArea bands derived from the plan+price series (charge / discharge
// / EV / peak-price windows, explained in the shared tooltip), and (b) the live
// last_plan.decisions pinned near "now" as markPoints + a "why now" caption.

const TRAIL_CAP = 7200; // 2 h @ 1 s — bounded buffer (brief §2)
const ACT_THRESH_W = 150; // sub-150 W is jitter, not a deliberate "action window"

const S = POWER_COLORS;

interface TrailPoint {
  ms: number;
  solar: number;
  home: number;
  battery: number; // + discharge / − charge
  grid: number; // + import / − export
  ev: number; // ≥0 charge
  soc: number | null;
}

interface Span {
  start: number;
  end: number;
}

/** Live battery-pack SOC — matches PowerFlow's device key, with a role fallback. */
function batterySoc(status?: HubStatus): number | null {
  const d = status?.devices;
  if (!d) return null;
  const direct = d['battery-0']?.soc_pct;
  if (direct != null) return direct;
  for (const dev of Object.values(d)) {
    if (dev.role === 'battery' && dev.soc_pct != null) return dev.soc_pct;
  }
  return null;
}

/** Merge consecutive qualifying slots into contiguous windows (end padded one slot). */
function buildSpans(pts: { ms: number; ok: boolean }[], slotMs: number): Span[] {
  const out: Span[] = [];
  let cur: Span | null = null;
  for (const p of pts) {
    if (p.ok) {
      if (cur) cur.end = p.ms + slotMs;
      else cur = { start: p.ms, end: p.ms + slotMs };
    } else if (cur) {
      out.push(cur);
      cur = null;
    }
  }
  if (cur) out.push(cur);
  return out;
}

/** The single widest window of a set (the one worth a visible label). */
function widest(spans: Span[]): Span | undefined {
  let best: Span | undefined;
  let bd = 0;
  for (const s of spans) {
    const d = s.end - s.start;
    if (d > bd) {
      bd = d;
      best = s;
    }
  }
  return best;
}

/** Nearest array element to `ms`, or undefined if none within `maxDist`. */
function nearest<T>(arr: T[], ms: number, getMs: (x: T) => number, maxDist: number): T | undefined {
  let best: T | undefined;
  let bd = Infinity;
  for (const it of arr) {
    const d = Math.abs(getMs(it) - ms);
    if (d < bd) {
      bd = d;
      best = it;
    }
  }
  return bd <= maxDist ? best : undefined;
}

function lerpHex(a: string, b: string, t: number): string {
  if (a[0] !== '#' || b[0] !== '#' || a.length < 7 || b.length < 7) return b;
  const pa = parseInt(a.slice(1, 7), 16);
  const pb = parseInt(b.slice(1, 7), 16);
  const r = Math.round(((pa >> 16) & 255) + (((pb >> 16) & 255) - ((pa >> 16) & 255)) * t);
  const g = Math.round(((pa >> 8) & 255) + (((pb >> 8) & 255) - ((pa >> 8) & 255)) * t);
  const bl = Math.round((pa & 255) + ((pb & 255) - (pa & 255)) * t);
  return `#${((1 << 24) + (r << 16) + (g << 8) + bl).toString(16).slice(1)}`;
}

/** Sample a light→dark sequential ramp at t∈[0,1] (TOU price magnitude). */
function rampColor(t: number, ramp: string[]): string {
  const n = ramp.length - 1;
  const x = Math.max(0, Math.min(1, t)) * n;
  const i = Math.floor(x);
  return i >= n ? ramp[n] : lerpHex(ramp[i], ramp[i + 1], x - i);
}

export function PlanVsActual({ status }: { status?: HubStatus }) {
  const { data: plan } = usePoll<HubPlan>(() => getJSON<HubPlan>('/api/hub/plan'), 30000);
  const [trail, setTrail] = useState<TrailPoint[]>([]);
  const lastTs = useRef<string>('');

  // Capture the full actual trail — now including home load and summed EV power
  // (task req 2), plus live battery SOC for the SOC lane.
  useEffect(() => {
    const ts = status?.timestamp;
    if (!ts || ts === lastTs.current || !status?.power) return;
    lastTs.current = ts;
    const p = status.power;
    setTrail((prev) =>
      pushCapped(
        prev,
        {
          ms: toMs(ts),
          solar: p.solar_W,
          home: p.load_W,
          battery: p.battery_W,
          grid: p.grid_W,
          ev: evPowerW(status),
          soc: batterySoc(status),
        },
        TRAIL_CAP
      )
    );
  }, [status]);

  const option = useMemo<EChartsOption>(() => {
    const ink = token('--ink');
    const ink2 = token('--ink-2');
    const ink3 = token('--ink-3');
    const line = token('--line');
    const card = token('--card');
    const greenInk = token('--green-ink');
    const cSolar = S.solar;
    const cHome = S.home;
    const cBatt = S.battery;
    const cEv = S.ev;
    const cGrid = S.grid;

    const nowMs = status?.timestamp ? toMs(status.timestamp) : Date.now();
    const decisions = status?.last_plan?.decisions ?? [];
    const slotMs = Math.max(1, plan?.slot_minutes ?? 15) * 60000;

    // ── plan series, in the DayDetail sign convention (demand ↑ · supply ↓) ──
    const solarF = plan?.solar_forecast ?? [];
    const loadF = plan?.load_forecast ?? [];
    const battP = plan?.battery_plan ?? [];
    const costP = plan?.cost_plan ?? [];
    const priceF = plan?.price_forecast ?? [];
    const evSeries = plan?.ev_plan ? Object.values(plan.ev_plan)[0] ?? [] : [];

    const planHome: [number, number][] = loadF.map((p) => [toMs(p.t), p.load_W]);
    const planSolar: [number, number][] = solarF.map((p) => [toMs(p.t), -p.solar_W]);
    const planBatt: [number, number][] = battP.map((p) => [toMs(p.t), -p.setpoint_W]);
    const planEv: [number, number][] = evSeries.map((p) => [toMs(p.t), -p.power_W]);
    const planGrid: [number, number][] = costP.map((p) => [toMs(p.t), p.grid_W]);
    const planSoc: [number, number | null][] = battP.map((p) => [toMs(p.t), p.soc_pct ?? null]);

    // ── actual trail (solid), same sign convention ──
    const aSolar: [number, number][] = trail.map((t) => [t.ms, -t.solar]);
    const aHome: [number, number][] = trail.map((t) => [t.ms, t.home]);
    const aBatt: [number, number][] = trail.map((t) => [t.ms, -t.battery]);
    const aEv: [number, number][] = trail.map((t) => [t.ms, t.ev]);
    const aGrid: [number, number][] = trail.map((t) => [t.ms, t.grid]);
    const aSoc: [number, number | null][] = trail.map((t) => [t.ms, t.soc]);

    // ── TOU price strip (import $/kWh → sequential amber ramp) ──
    const imps = priceF.map((p) => p.import_per_kwh);
    const pMin = imps.length ? Math.min(...imps) : 0;
    const pMax = imps.length ? Math.max(...imps) : 1;
    const pSpan = pMax - pMin;
    const priceData = priceF.map((p) => ({ value: [toMs(p.t), toMs(p.t) + slotMs, p.import_per_kwh] }));
    const priceColors = priceF.map((p) => rampColor(pSpan > 1e-9 ? (p.import_per_kwh - pMin) / pSpan : 0.5, SEQUENTIAL_RAMP));

    // ── rationale windows derived from the plan (task req 3a) ──
    const peakCut = pMin + 0.62 * pSpan;
    const chargeSpans = buildSpans(battP.map((p) => ({ ms: toMs(p.t), ok: p.setpoint_W < -ACT_THRESH_W })), slotMs);
    const dischargeSpans = buildSpans(battP.map((p) => ({ ms: toMs(p.t), ok: p.setpoint_W > ACT_THRESH_W })), slotMs);
    const evSpans = buildSpans(evSeries.map((p) => ({ ms: toMs(p.t), ok: p.power_W < -ACT_THRESH_W })), slotMs);
    const peakSpans = pSpan > 1e-6 ? buildSpans(priceF.map((p) => ({ ms: toMs(p.t), ok: p.import_per_kwh >= peakCut })), slotMs) : [];
    const exportSpans = buildSpans(costP.map((p) => ({ ms: toMs(p.t), ok: p.grid_W < -ACT_THRESH_W })), slotMs);

    const bands = [
      { spans: peakSpans, color: cSolar, opacity: 0.07, label: 'peak price' },
      { spans: chargeSpans, color: cBatt, opacity: 0.06, label: 'charge' },
      { spans: dischargeSpans, color: cBatt, opacity: 0.12, label: 'shave peak' },
      { spans: evSpans, color: cEv, opacity: 0.1, label: 'EV charge' },
      { spans: exportSpans, color: cGrid, opacity: 0.06, label: 'export' },
    ];
    const markAreaData: MarkAreaComponentOption['data'] = [];
    for (const b of bands) {
      const wide = widest(b.spans);
      for (const s of b.spans) {
        markAreaData!.push([
          {
            xAxis: s.start,
            itemStyle: { color: b.color, opacity: b.opacity },
            label:
              wide && s.start === wide.start
                ? { show: true, formatter: b.label, position: 'insideTop', color: ink2, fontSize: 10, fontWeight: 600 }
                : { show: false },
          },
          { xAxis: s.end },
        ]);
      }
    }

    // "now" reference line (arrival-time, from the live status) + a 0-kW rule.
    const nowMark: MarkLineComponentOption = {
      silent: true,
      symbol: 'none',
      data: [
        {
          xAxis: nowMs,
          label: { show: true, formatter: 'now', position: 'insideEndTop', color: ink3, fontSize: 10 },
          lineStyle: { color: ink2, type: 'dashed', width: 1 },
        },
        { yAxis: 0, label: { show: false }, lineStyle: { color: line, type: 'solid', width: 1 } },
      ],
    };
    const nowMarkPlain: MarkLineComponentOption = {
      silent: true,
      symbol: 'none',
      data: [{ xAxis: nowMs }],
      lineStyle: { color: ink2, type: 'dashed', width: 1 },
      label: { show: false },
    };

    // Live decisions pinned near "now" (task req 3b).
    let yMag = 3000;
    const bump = (arr: [number, number][]) => {
      for (const p of arr) {
        const a = Math.abs(p[1]);
        if (a > yMag) yMag = a;
      }
    };
    bump(planGrid);
    bump(planHome);
    bump(planSolar);
    bump(planBatt);
    bump(planEv);
    bump(aGrid);
    const decoMark: MarkPointComponentOption = {
      silent: true,
      data: decisions.slice(0, 3).map((d, i) => ({
        name: d.rule,
        coord: [nowMs, yMag * (0.92 - i * 0.22)],
        symbol: 'circle',
        symbolSize: 7,
        itemStyle: { color: greenInk },
        label: {
          show: true,
          formatter: d.rule,
          position: 'right',
          color: ink2,
          fontSize: 9,
          fontFamily: 'ui-monospace, monospace',
          backgroundColor: card,
          borderColor: line,
          borderWidth: 1,
          borderRadius: 3,
          padding: [1, 4],
        },
      })),
    };

    // common x-range so all three lanes align cell-for-cell.
    const times: number[] = [];
    if (trail.length) times.push(trail[0].ms, trail[trail.length - 1].ms);
    for (const a of [planSolar, planHome, planBatt, planEv, planGrid]) {
      if (a.length) times.push(a[0][0], a[a.length - 1][0]);
    }
    for (const p of priceData) times.push(p.value[0], p.value[1]);
    const xMin = times.length ? Math.min(...times) : nowMs - 3600000;
    const xMax = times.length ? Math.max(...times) : nowMs + 86400000;

    // Plan = a soft ghosted forecast envelope (faint fill, barely-there dashed
    // outline). Actual = a crisp bold line drawn ON TOP. The two must read as
    // "shaded region = plan · solid line = live" at a glance.
    const planArea = (name: string, color: string, data: [number, number][]) => ({
      name,
      type: 'line' as const,
      stack: 'plan',
      xAxisIndex: 0,
      yAxisIndex: 0,
      data,
      showSymbol: false,
      silent: true,
      lineStyle: { width: 1, color, opacity: 0.28, type: 'dashed' as const },
      areaStyle: { color, opacity: 0.1 },
      itemStyle: { color },
      z: 2,
      sampling: 'lttb' as const,
    });
    const actualLine = (name: string, color: string, data: [number, number][], z = 5, width = 2.6) => ({
      name,
      type: 'line' as const,
      xAxisIndex: 0,
      yAxisIndex: 0,
      data,
      showSymbol: false,
      lineStyle: { width, color, opacity: 1 },
      itemStyle: { color },
      z,
      sampling: 'lttb' as const,
    });

    const renderPrice: CustomSeriesRenderItem = (params, api) => {
      const t0 = api.value(0) as number;
      const t1 = api.value(1) as number;
      const topLeft = api.coord([t0, 1]);
      const botRight = api.coord([t1, 0]);
      const color = priceColors[params.dataIndex] ?? cSolar;
      return {
        type: 'rect',
        shape: {
          x: topLeft[0],
          y: topLeft[1],
          width: Math.max(0.5, botRight[0] - topLeft[0]),
          height: botRight[1] - topLeft[1],
        },
        style: { fill: color },
      };
    };

    const dot = (c: string) =>
      `<span style="display:inline-block;width:8px;height:8px;border-radius:2px;background:${c};margin-right:6px;vertical-align:middle"></span>`;

    return {
      backgroundColor: 'transparent',
      color: [cSolar, cHome, cBatt, cEv, cGrid],
      textStyle: { color: ink },
      legend: {
        top: 10,
        left: 0,
        itemWidth: 16,
        itemHeight: 9,
        textStyle: { color: ink2, fontSize: 11 },
        data: ['Solar', 'Home', 'Battery', 'EV', 'Grid'],
      },
      axisPointer: { link: [{ xAxisIndex: 'all' }] },
      tooltip: {
        trigger: 'axis',
        confine: true,
        backgroundColor: card,
        borderColor: line,
        borderWidth: 1,
        textStyle: { color: ink, fontSize: 12 },
        axisPointer: { type: 'cross', lineStyle: { color: ink3, type: 'dashed' }, crossStyle: { color: ink3 } },
        formatter: (raw) => {
          const arr = Array.isArray(raw) ? raw : [raw];
          const ms = Number((arr[0] as { axisValue?: number })?.axisValue);
          if (!Number.isFinite(ms)) return '';
          const when = new Date(ms).toLocaleString('en-US', {
            month: 'short',
            day: 'numeric',
            hour: '2-digit',
            minute: '2-digit',
            hour12: false,
          });
          const gp = nearest(planGrid, ms, (p) => p[0], slotMs);
          const sp = nearest(planSolar, ms, (p) => p[0], slotMs);
          const hp = nearest(planHome, ms, (p) => p[0], slotMs);
          const bp = nearest(planBatt, ms, (p) => p[0], slotMs);
          const ep = nearest(planEv, ms, (p) => p[0], slotMs);
          const scp = nearest(planSoc, ms, (p) => p[0], slotMs);
          const prc = nearest(priceF, ms, (p) => toMs(p.t), slotMs);
          const ta = nearest(trail, ms, (t) => t.ms, 60000);

          const row = (color: string, label: string, planStr: string, actStr: string) =>
            `<div style="display:flex;justify-content:space-between;gap:14px;margin-top:2px">` +
            `<span>${dot(color)}${label}</span>` +
            `<span style="font-variant-numeric:tabular-nums;color:${ink2}">${planStr}` +
            (actStr ? ` <span style="color:${ink3}">·</span> <span style="color:${ink}">${actStr}</span>` : '') +
            `</span></div>`;

          const battDir = (w: number) => (w > 0 ? ' dis' : w < 0 ? ' chg' : '');
          const gridDir = (w: number) => (w >= 0 ? ' imp' : ' exp');
          let html = `<div style="font-weight:600;margin-bottom:4px">${when}</div>`;
          html += `<div style="font-size:10px;color:${ink3};margin-bottom:3px">plan <span style="color:${ink2}">·</span> actual</div>`;
          if (sp) html += row(cSolar, 'Solar', formatWatts(-sp[1]), ta ? formatWatts(ta.solar) : '');
          if (hp) html += row(cHome, 'Home', formatWatts(hp[1]), ta ? formatWatts(ta.home) : '');
          if (bp) {
            const planW = -bp[1];
            html += row(cBatt, 'Battery', formatWatts(Math.abs(planW)) + battDir(planW), ta ? formatWatts(Math.abs(ta.battery)) + battDir(ta.battery) : '');
          }
          if (ep) html += row(cEv, 'EV', formatWatts(ep[1]), ta ? formatWatts(ta.ev) : '');
          if (gp) html += row(cGrid, 'Grid', formatWatts(Math.abs(gp[1])) + gridDir(gp[1]), ta ? formatWatts(Math.abs(ta.grid)) + gridDir(ta.grid) : '');
          const socPlan = scp && scp[1] != null ? formatPercent(scp[1], 0) : '';
          const socAct = ta && ta.soc != null ? formatPercent(ta.soc, 0) : '';
          if (socPlan || socAct) html += row(cBatt, 'SOC', socPlan || '—', socAct);
          if (prc) {
            html +=
              `<div style="margin-top:5px;padding-top:4px;border-top:1px solid ${line};font-size:11px;color:${ink2}">` +
              `${(prc.import_per_kwh * 100).toFixed(1)}¢ import <span style="color:${ink3}">·</span> ` +
              `${(prc.delivery_per_kwh * 100).toFixed(1)}¢ delivery <span style="color:${ink3}">·</span> ` +
              `${(prc.export_per_kwh * 100).toFixed(1)}¢ export</div>`;
          }
          const active: string[] = [];
          const inSpan = (spans: Span[]) => spans.some((s) => ms >= s.start && ms < s.end);
          if (inSpan(peakSpans)) active.push('Peak price — costliest grid energy');
          if (inSpan(chargeSpans)) active.push('Charging — storing cheap / surplus energy');
          if (inSpan(dischargeSpans)) active.push('Discharging — shaving the priced peak');
          if (inSpan(evSpans)) active.push('EV charging window');
          if (inSpan(exportSpans)) active.push('Exporting surplus to grid');
          if (active.length) {
            html += `<div style="margin-top:5px;padding-top:4px;border-top:1px solid ${line};font-size:11px;color:${greenInk}">`;
            html += active.map((a) => `▸ ${a}`).join('<br/>');
            html += `</div>`;
          }
          return html;
        },
      },
      grid: [
        { left: 58, right: 20, top: 46, height: 174 },
        { left: 58, right: 20, top: 248, height: 44 },
        { left: 58, right: 20, top: 308, height: 26 },
      ],
      xAxis: [
        { type: 'time', gridIndex: 0, min: xMin, max: xMax, axisLabel: { show: false }, axisLine: { lineStyle: { color: line } }, axisTick: { show: false } },
        { type: 'time', gridIndex: 1, min: xMin, max: xMax, axisLabel: { show: false }, axisLine: { lineStyle: { color: line } }, axisTick: { show: false } },
        { type: 'time', gridIndex: 2, min: xMin, max: xMax, axisLabel: { color: ink3, fontSize: 10, hideOverlap: true }, axisLine: { lineStyle: { color: line } }, axisTick: { show: false } },
      ],
      yAxis: [
        {
          type: 'value',
          gridIndex: 0,
          name: 'kW',
          nameTextStyle: { color: ink3, fontSize: 11, align: 'right' },
          axisLabel: { color: ink3, fontSize: 11, formatter: (v: number) => (v / 1000).toFixed(Math.abs(v) >= 10000 ? 0 : 1) },
          splitLine: { lineStyle: { color: line } },
          axisLine: { show: false },
        },
        {
          type: 'value',
          gridIndex: 1,
          name: 'SOC %',
          min: 0,
          max: 100,
          interval: 50,
          nameTextStyle: { color: ink3, fontSize: 10, align: 'right' },
          axisLabel: { color: ink3, fontSize: 10 },
          splitLine: { lineStyle: { color: line } },
          axisLine: { show: false },
        },
        { type: 'value', gridIndex: 2, min: 0, max: 1, show: false },
      ],
      series: [
        // PLAN — stacked energy landscape (Home ↑ · Solar/Battery/EV ↓).
        planArea('Home', cHome, planHome),
        planArea('Solar', cSolar, planSolar),
        planArea('Battery', cBatt, planBatt),
        planArea('EV', cEv, planEv),
        // PLAN net grid line (import above 0 / export below) + all lane-0 overlays.
        {
          name: 'Grid',
          type: 'line',
          xAxisIndex: 0,
          yAxisIndex: 0,
          data: planGrid,
          showSymbol: false,
          lineStyle: { width: 1.5, color: cGrid, type: 'dashed', opacity: 0.4 },
          itemStyle: { color: cGrid },
          z: 3,
          sampling: 'lttb',
          markArea: { silent: true, data: markAreaData },
          markLine: nowMark,
          markPoint: decoMark,
        },
        // ACTUAL — live measured trail (solid).
        actualLine('Solar', cSolar, aSolar),
        actualLine('Home', cHome, aHome),
        actualLine('Battery', cBatt, aBatt),
        actualLine('EV', cEv, aEv),
        actualLine('Grid', cGrid, aGrid, 6, 2.5),
        // SOC lane (%) — plan dashed + area, actual solid.
        {
          name: 'SOC',
          type: 'line',
          xAxisIndex: 1,
          yAxisIndex: 1,
          data: planSoc,
          connectNulls: true,
          showSymbol: false,
          silent: true,
          lineStyle: { width: 1.5, color: cBatt, opacity: 0.6, type: 'dashed' },
          areaStyle: { color: cBatt, opacity: 0.08 },
          itemStyle: { color: cBatt },
          z: 2,
          markLine: nowMarkPlain,
        },
        {
          name: 'SOC',
          type: 'line',
          xAxisIndex: 1,
          yAxisIndex: 1,
          data: aSoc,
          connectNulls: false,
          showSymbol: false,
          lineStyle: { width: 2, color: cBatt },
          itemStyle: { color: cBatt },
          z: 3,
        },
        // Price lane ($/kWh) — TOU heatmap strip on the shared time axis.
        {
          name: 'Price',
          type: 'custom',
          xAxisIndex: 2,
          yAxisIndex: 2,
          data: priceData,
          renderItem: renderPrice,
          clip: true,
          silent: true,
          z: 1,
        },
        {
          type: 'line',
          xAxisIndex: 2,
          yAxisIndex: 2,
          data: [
            [nowMs, 0],
            [nowMs, 1],
          ],
          showSymbol: false,
          silent: true,
          lineStyle: { color: ink2, width: 1, type: 'dashed' },
          z: 4,
        },
      ],
    };
  }, [plan, trail, status]);

  const hasAny = (plan?.solar_forecast?.length ?? 0) > 0 || (plan?.cost_plan?.length ?? 0) > 0 || trail.length > 0;
  const genAgeS = plan ? (Date.now() - new Date(plan.generated_at).getTime()) / 1000 : NaN;
  const decisions = status?.last_plan?.decisions ?? [];
  const peakRate = plan?.price_forecast?.length ? Math.max(...plan.price_forecast.map((p) => p.import_per_kwh)) : NaN;

  return (
    <div className="ops-card">
      <div className="ops-card-head">
        <h2 className="card-title">Plan vs Actual</h2>
        <div className="ops-head-meta">shaded + dashed = plan (forecast) · <b>bold solid = actual (live)</b> · demand ↑ / supply ↓</div>
      </div>
      {!hasAny ? (
        <p className="ops-empty">No plan yet — the chart draws once the hub publishes a 24 h forecast and the measured trail begins to fill.</p>
      ) : (
        <EChart option={option} style={{ height: 384 }} streaming />
      )}

      {decisions.length > 0 && (
        <div className="ops-plan-why">
          <span className="ops-plan-why-label">Why now</span>
          {decisions.slice(0, 2).map((d, i) => (
            <span className="ops-plan-why-item" key={i}>
              <span className="ops-chip ops-chip-rule" title="Decision rule">{d.rule}</span>
              <span className="ops-plan-why-txt">
                {d.reason} <span className="ops-feed-arrow">→</span> {d.impact}
              </span>
            </span>
          ))}
        </div>
      )}

      <div className="ops-stat-row">
        <div>
          <div className="ops-stat-label">Plan cost</div>
          <div className="ops-stat-val accent">{plan ? formatDollars(plan.total_cost) : '—'}</div>
        </div>
        <div>
          <div className="ops-stat-label">Peak rate</div>
          <div className="ops-stat-val">{Number.isFinite(peakRate) ? `${formatDollars(peakRate)}/kWh` : '—'}</div>
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
