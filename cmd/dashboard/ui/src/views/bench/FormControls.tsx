// Small shared inputs for the inject/control forms across the four sim
// cards — kept dumb (controlled string state, parsed by the caller on
// submit) to mirror the legacy dashboard's "leave blank to omit" semantics
// without wiring a form library (brief: no new deps).
import type { ReactNode } from 'react';

export interface NumberFieldProps {
  label: string;
  value: string;
  onChange: (v: string) => void;
  min?: number;
  max?: number;
  step?: number;
  placeholder?: string;
}

export function NumberField({ label, value, onChange, min, max, step, placeholder }: NumberFieldProps) {
  return (
    <label style={{ display: 'flex', flexDirection: 'column', gap: 2, fontSize: 11, color: 'var(--ink-2)' }}>
      {label}
      <input
        type="number"
        value={value}
        min={min}
        max={max}
        step={step}
        placeholder={placeholder}
        onChange={(e) => onChange(e.target.value)}
        className="mono"
        style={{
          fontSize: 12,
          padding: '5px 7px',
          border: '1px solid var(--line)',
          borderRadius: 6,
          background: 'var(--card)',
          color: 'var(--ink)',
          width: '100%',
        }}
      />
    </label>
  );
}

export interface TriStateSelectProps {
  label: string;
  value: '' | '1' | '0';
  onChange: (v: '' | '1' | '0') => void;
  onLabel?: string;
  offLabel?: string;
}

/** "— / on / off" select, matching legacy's Conn override pattern (leave unset to omit). */
export function TriStateSelect({ label, value, onChange, onLabel = '1 (on)', offLabel = '0 (off)' }: TriStateSelectProps) {
  return (
    <label style={{ display: 'flex', flexDirection: 'column', gap: 2, fontSize: 11, color: 'var(--ink-2)' }}>
      {label}
      <select
        value={value}
        onChange={(e) => onChange(e.target.value as '' | '1' | '0')}
        style={{
          fontSize: 12,
          padding: '5px 7px',
          border: '1px solid var(--line)',
          borderRadius: 6,
          background: 'var(--card)',
          color: 'var(--ink)',
        }}
      >
        <option value="">—</option>
        <option value="1">{onLabel}</option>
        <option value="0">{offLabel}</option>
      </select>
    </label>
  );
}

export function ActionButton({
  children,
  onClick,
  primary,
}: {
  children: ReactNode;
  onClick: () => void;
  primary?: boolean;
}) {
  return (
    <button
      type="button"
      onClick={onClick}
      style={{
        fontSize: 12,
        padding: '5px 10px',
        borderRadius: 6,
        cursor: 'pointer',
        border: `1px solid ${primary ? 'var(--green-ink)' : 'var(--line)'}`,
        background: primary ? 'var(--green-ink)' : 'transparent',
        color: primary ? '#fff' : 'var(--ink-2)',
        fontWeight: primary ? 600 : 400,
      }}
    >
      {children}
    </button>
  );
}

/** Quiet inline ✓/✗ status text, cleared by the caller after a short delay. */
export function InlineStatus({ text, ok }: { text: string; ok: boolean }) {
  return (
    <span style={{ fontSize: 11, color: ok ? 'var(--s-good)' : 'var(--s-critical)' }}>{text}</span>
  );
}
