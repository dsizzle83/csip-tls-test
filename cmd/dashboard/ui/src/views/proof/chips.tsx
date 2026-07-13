// Small presentational chips shared across the Proof panels. Verdict chips
// always carry icon + label + color (never color alone) per DESIGN_BRIEF.md §2.

import type { ReactNode } from 'react';
import { verdictMeta } from './verdict';

/** Verdict pill: colored icon + word, tinted background. */
export function VerdictChip({ verdict, count }: { verdict: string; count?: number }) {
  const m = verdictMeta(verdict);
  return (
    <span
      className="pf-chip pf-chip-verdict"
      style={{
        color: `var(${m.cssVar})`,
        borderColor: `color-mix(in srgb, var(${m.cssVar}) 35%, white)`,
        background: `color-mix(in srgb, var(${m.cssVar}) 10%, white)`,
      }}
    >
      <span aria-hidden="true">{m.icon}</span>
      {m.label}
      {count != null && <span className="pf-chip-count">{count}</span>}
    </span>
  );
}

/** Neutral metadata chip (category, source, badges). */
export function Chip({
  children,
  tone = 'neutral',
  title,
}: {
  children: ReactNode;
  tone?: 'neutral' | 'sage' | 'mono';
  title?: string;
}) {
  return (
    <span className={`pf-chip pf-chip-${tone}`} title={title}>
      {children}
    </span>
  );
}

/** A labelled metric chip: "peak 1.2 kW" — label recessive, value ink. */
export function MetricChip({ label, value }: { label: string; value: string }) {
  return (
    <span className="pf-chip pf-metric">
      <span className="pf-metric-label">{label}</span>
      <span className="pf-metric-value mono">{value}</span>
    </span>
  );
}
