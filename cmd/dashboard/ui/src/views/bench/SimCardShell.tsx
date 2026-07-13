import type { ReactNode } from 'react';

export interface SimCardShellProps {
  title: string;
  /** Entity accent color (CSS var string) — a top stripe + swatch dot, never the title text color (brief: text wears ink tokens, never series color). */
  accent: string;
  statusLabel: string;
  statusOk: boolean;
  children: ReactNode;
}

export function SimCardShell({ title, accent, statusLabel, statusOk, children }: SimCardShellProps) {
  return (
    <div className="card card-pad" style={{ borderTop: `3px solid ${accent}`, display: 'flex', flexDirection: 'column', gap: 12 }}>
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
          <span
            aria-hidden="true"
            style={{ width: 8, height: 8, borderRadius: '50%', background: accent, display: 'inline-block' }}
          />
          <h2 className="card-title" style={{ margin: 0 }}>
            {title}
          </h2>
        </div>
        <span
          className="mono"
          style={{ fontSize: 11, color: statusOk ? 'var(--s-good)' : 'var(--ink-3)' }}
        >
          {statusLabel}
        </span>
      </div>
      {children}
    </div>
  );
}

/** One telemetry row: label left, value right, mono tabular-nums value. */
export function TelemRow({ label, value, valueColor }: { label: string; value: string; valueColor?: string }) {
  return (
    <div style={{ display: 'flex', justifyContent: 'space-between', fontSize: 13, padding: '2px 0' }}>
      <span style={{ color: 'var(--ink-2)' }}>{label}</span>
      <span className="mono" style={{ color: valueColor ?? 'var(--ink)' }}>
        {value}
      </span>
    </div>
  );
}

export function Expander({
  label,
  open,
  onToggle,
  children,
}: {
  label: string;
  open: boolean;
  onToggle: () => void;
  children: ReactNode;
}) {
  return (
    <div>
      <button
        type="button"
        onClick={onToggle}
        style={{
          fontSize: 11,
          color: 'var(--ink-2)',
          background: 'none',
          border: 'none',
          cursor: 'pointer',
          padding: '4px 0',
          display: 'flex',
          alignItems: 'center',
          gap: 4,
        }}
      >
        <span aria-hidden="true">{open ? '▾' : '▸'}</span>
        {label}
      </button>
      {open && <div style={{ maxHeight: 320, overflowY: 'auto', border: '1px solid var(--line)', borderRadius: 8 }}>{children}</div>}
    </div>
  );
}
