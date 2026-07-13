// Small pure helpers shared across the /ops panels. Kept local to the view
// (task: shared utilities go inside src/views/ops/).

import type { HubStatus } from './types';

export function clamp(v: number, lo: number, hi: number): number {
  return v < lo ? lo : v > hi ? hi : v;
}

/** Sum of instantaneous EV charge power across all stations (W, ≥0). */
export function evPowerW(status?: HubStatus): number {
  if (!status?.evse_stations) return 0;
  return status.evse_stations.reduce((s, e) => s + (e.power_W || 0), 0);
}

export interface FlowNodes {
  solar: number;
  battery: number; // >0 discharge, <0 charge
  grid: number; // >0 import, <0 export
  ev: number; // ≥0 charging
  home: number; // consumption, always ≥0-ish
}

/**
 * Derive the five power-flow node values from a status snapshot. Home load is
 * reconstructed from the same components as the diagram so the node values and
 * link balance stay internally consistent: home = solar + battery + grid − ev
 * (verified against the hub's own power.load_W on live data).
 */
export function flowNodes(status?: HubStatus): FlowNodes {
  const p = status?.power;
  const solar = p?.solar_W ?? 0;
  const battery = p?.battery_W ?? 0;
  const grid = p?.grid_W ?? 0;
  const ev = evPowerW(status);
  const home = solar + battery + grid - ev;
  return { solar, battery, grid, ev, home };
}

/** Stroke width ∝ |W|, clamped to the brief's 1.5–8 px band. */
export function linkWidth(watts: number, refMax = 7000): number {
  const n = Math.min(1, Math.abs(watts) / refMax);
  return 1.5 + 6.5 * n;
}

/** Push onto a bounded ring, returning a NEW array capped at `cap` (newest last). */
export function pushCapped<T>(arr: T[], item: T, cap: number): T[] {
  const next = arr.length >= cap ? arr.slice(arr.length - cap + 1) : arr.slice();
  next.push(item);
  return next;
}

/** Gridsim/hub "now" in epoch seconds, honoring the reported clock skew. */
export function serverNowS(status?: HubStatus): number {
  return Math.floor(Date.now() / 1000) + (status?.clock_offset_s ?? 0);
}

/** mm:ss countdown text; clamps at 00:00. */
export function formatCountdown(seconds: number): string {
  const s = Math.max(0, Math.floor(seconds));
  const m = Math.floor(s / 60);
  const sec = s % 60;
  return `${String(m).padStart(2, '0')}:${String(sec).padStart(2, '0')}`;
}

/** Δt in seconds → compact "1.2 s" / "23 s". */
export function formatDelta(seconds: number): string {
  if (!Number.isFinite(seconds)) return '—';
  if (seconds < 10) return `${seconds.toFixed(1)} s`;
  return `${Math.round(seconds)} s`;
}

/** ISO/epoch → epoch ms for ECharts time axis. */
export function toMs(t: string | number): number {
  if (typeof t === 'number') return t < 1e12 ? t * 1000 : t;
  return new Date(t).getTime();
}

export interface LimitEval {
  label: string; // e.g. "Export ≤ 1.00 kW"
  metricW: number; // the measured quantity being limited (W)
  limitW: number;
  within: boolean; // metric ≤ limit + tolerance
}

const COMPLIANCE_TOL_W = 150;

/**
 * Given an adopted DERControlBase and the live power snapshot, work out which
 * limit is binding and whether the meter is inside it (+150 W tolerance).
 * Returns null when the control carries no measurable numeric limit
 * (e.g. the default control, or a bare energize/connect flip).
 */
export function evalLimit(
  base: { exp_lim_W?: number; imp_lim_W?: number; gen_lim_W?: number; load_lim_W?: number } | undefined,
  power: { solar_W: number; grid_W: number; load_W: number } | undefined,
  tol = COMPLIANCE_TOL_W
): LimitEval | null {
  if (!base || !power) return null;
  const kw = (w: number) => `${(w / 1000).toFixed(2)} kW`;
  if (base.exp_lim_W != null) {
    const metricW = Math.max(0, -power.grid_W);
    return { label: `Export ≤ ${kw(base.exp_lim_W)}`, metricW, limitW: base.exp_lim_W, within: metricW <= base.exp_lim_W + tol };
  }
  if (base.imp_lim_W != null) {
    const metricW = Math.max(0, power.grid_W);
    return { label: `Import ≤ ${kw(base.imp_lim_W)}`, metricW, limitW: base.imp_lim_W, within: metricW <= base.imp_lim_W + tol };
  }
  if (base.gen_lim_W != null) {
    const metricW = Math.max(0, power.solar_W);
    return { label: `Generation ≤ ${kw(base.gen_lim_W)}`, metricW, limitW: base.gen_lim_W, within: metricW <= base.gen_lim_W + tol };
  }
  if (base.load_lim_W != null) {
    const metricW = Math.max(0, power.load_W);
    return { label: `Load ≤ ${kw(base.load_lim_W)}`, metricW, limitW: base.load_lim_W, within: metricW <= base.load_lim_W + tol };
  }
  return null;
}
