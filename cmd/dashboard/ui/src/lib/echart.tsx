import { useEffect, useRef } from 'react';
import type { CSSProperties } from 'react';
import * as echarts from 'echarts';
import type { EChartsOption, ECharts } from 'echarts';
import { token } from './colors';

export interface EChartProps {
  /** Full ECharts option object. Re-applied via setOption whenever this reference changes — memoize it (useMemo/useState), don't build it inline every render. */
  option: EChartsOption;
  /** Inline style for the chart container. Must resolve to a non-zero height (ECharts can't size to 0); e.g. { height: 280 }. */
  style?: CSSProperties;
  className?: string;
  /**
   * Streaming/live charts must disable animation per DESIGN_BRIEF.md §2
   * ("disable default animation on streaming charts; 250ms ease on static
   * renders"). Default false (static chart, 250ms ease-in). Pass true for
   * high-frequency updating charts (Ops power flow, live QA timeline).
   */
  streaming?: boolean;
  /** Forwarded to chart.setOption(option, notMerge). Default false (merge — cheaper for incremental updates like ticking a live series). */
  notMerge?: boolean;
  /** SSE/DOM-style event map, wired with chart.on/off (e.g. { click: (p) => ... }). */
  onEvents?: Record<string, (params: unknown) => void>;
  /** Fires once after echarts.init, for imperative access (dispatchAction, getDataURL, etc). */
  onReady?: (chart: ECharts) => void;
}

function briefAxisDefaults() {
  return {
    axisLine: { lineStyle: { color: token('--line') } },
    axisTick: { show: false },
    axisLabel: { color: token('--ink-3'), fontSize: 11 },
    splitLine: { lineStyle: { color: token('--line') } },
  };
}

/**
 * Merges DESIGN_BRIEF.md §2/§3 chart defaults under the caller's option:
 * white background, ink text, --line hairline grid/axis lines, --ink-3 11px
 * axis labels, no chart borders. Any field the caller sets on xAxis/yAxis/
 * textStyle wins outright (shallow merge, not deep) — set the whole
 * sub-object if you need to override more than one of its fields.
 */
function withBriefDefaults(option: EChartsOption): EChartsOption {
  const merged: EChartsOption = { ...option };
  merged.backgroundColor = option.backgroundColor ?? '#FFFFFF';
  merged.textStyle = {
    color: token('--ink'),
    fontFamily: 'system-ui, -apple-system, sans-serif',
    ...option.textStyle,
  };

  // Typed per-call (not a shared helper) — ECharts' XAXisOption/YAXisOption
  // are structurally similar but nominally distinct, so a single generic
  // applyAxis(axis) can't satisfy both call sites at once.
  if (option.xAxis) {
    const defaults = briefAxisDefaults();
    merged.xAxis = Array.isArray(option.xAxis)
      ? option.xAxis.map((a) => ({ ...defaults, ...a }))
      : { ...defaults, ...option.xAxis };
  }
  if (option.yAxis) {
    const defaults = briefAxisDefaults();
    merged.yAxis = Array.isArray(option.yAxis)
      ? option.yAxis.map((a) => ({ ...defaults, ...a }))
      : { ...defaults, ...option.yAxis };
  }

  return merged;
}

/**
 * Thin React wrapper around ECharts: inits once per mount, calls setOption
 * whenever `option` changes by reference, resizes via ResizeObserver, and
 * disposes on unmount. Applies brief chart defaults (see withBriefDefaults)
 * that the passed `option` can override field-by-field.
 *
 * Usage:
 *   <EChart option={option} style={{ height: 280 }} />          // static
 *   <EChart option={liveOption} style={{ height: 260 }} streaming />  // no animation
 */
export function EChart({
  option,
  style,
  className,
  streaming = false,
  notMerge = false,
  onEvents,
  onReady,
}: EChartProps) {
  const containerRef = useRef<HTMLDivElement | null>(null);
  const chartRef = useRef<ECharts | null>(null);
  const onReadyRef = useRef(onReady);
  onReadyRef.current = onReady;

  // Init once; dispose on unmount.
  useEffect(() => {
    if (!containerRef.current) return;
    const chart = echarts.init(containerRef.current);
    chartRef.current = chart;
    onReadyRef.current?.(chart);

    const ro = new ResizeObserver(() => chart.resize());
    ro.observe(containerRef.current);

    return () => {
      ro.disconnect();
      chart.dispose();
      chartRef.current = null;
    };
  }, []);

  // Re-apply option (+ brief defaults) whenever it changes.
  useEffect(() => {
    const chart = chartRef.current;
    if (!chart) return;
    const withDefaults = withBriefDefaults(option);
    // Streaming charts never animate; static charts default to a 250ms ease
    // unless the caller explicitly set animation fields.
    if (streaming) {
      withDefaults.animation = false;
    } else {
      withDefaults.animation = option.animation ?? true;
      withDefaults.animationDuration = option.animationDuration ?? 250;
      withDefaults.animationEasing = option.animationEasing ?? 'cubicOut';
    }
    chart.setOption(withDefaults, notMerge);
  }, [option, streaming, notMerge]);

  // (Re)wire event handlers.
  useEffect(() => {
    const chart = chartRef.current;
    if (!chart || !onEvents) return;
    for (const [name, handler] of Object.entries(onEvents)) {
      chart.on(name, handler);
    }
    return () => {
      for (const name of Object.keys(onEvents)) {
        chart.off(name);
      }
    };
  }, [onEvents]);

  return (
    <div
      ref={containerRef}
      className={className}
      style={{ width: '100%', height: '100%', ...style }}
    />
  );
}
