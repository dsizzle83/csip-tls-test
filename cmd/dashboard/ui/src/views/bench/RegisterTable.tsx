import { Fragment, useMemo } from 'react';
import type { RegisterMap } from './types';
import type { RegAnnotation } from './registerAnnotations';

export interface RegisterTableProps {
  registers: RegisterMap;
  annotations: Record<number, RegAnnotation>;
  ranges: Record<string, readonly [number, number]>;
}

function sectionFor(addr: number, ranges: Record<string, readonly [number, number]>): string {
  for (const [name, [lo, hi]] of Object.entries(ranges)) {
    if (addr >= lo && addr <= hi) return name;
  }
  return '?';
}

/** int16 registers wrap at ±32,767 (CLAUDE.md invariant) — signed reading, not a true SF-scaled value. */
function signed16(raw: number): number {
  return raw > 32767 ? raw - 65536 : raw;
}

/**
 * Mono register dump, grouped by SunSpec model section (matching legacy
 * dashboard.html's renderRegTable semantics): Addr / Name / Raw (hex) /
 * Scaled (signed int16 reading) columns, description on hover.
 */
export function RegisterTable({ registers, annotations, ranges }: RegisterTableProps) {
  const entries = useMemo(
    () =>
      Object.entries(registers)
        .map(([addr, val]) => [Number(addr), val] as const)
        .sort((a, b) => a[0] - b[0]),
    [registers]
  );

  if (entries.length === 0) {
    return <div className="empty-state">No register data.</div>;
  }

  let currentSection: string | null = null;

  return (
    <div style={{ overflowX: 'auto' }}>
      <table className="mono" style={{ width: '100%', borderCollapse: 'collapse', fontSize: 12 }}>
        <thead>
          <tr style={{ textAlign: 'left', color: 'var(--ink-3)' }}>
            <th style={{ padding: '4px 8px' }}>Addr</th>
            <th style={{ padding: '4px 8px' }}>Name</th>
            <th style={{ padding: '4px 8px' }}>Raw</th>
            <th style={{ padding: '4px 8px' }}>Scaled</th>
          </tr>
        </thead>
        <tbody>
          {entries.map(([addr, raw]) => {
            const section = sectionFor(addr, ranges);
            const showHeader = section !== currentSection;
            currentSection = section;
            const ann = annotations[addr];
            const range = ranges[section];
            return (
              <Fragment key={addr}>
                {showHeader && (
                  <tr>
                    <td
                      colSpan={4}
                      style={{
                        padding: '8px 8px 2px',
                        color: 'var(--ink-2)',
                        fontWeight: 600,
                        fontSize: 11,
                        textTransform: 'uppercase',
                        letterSpacing: '0.04em',
                      }}
                    >
                      {section}
                      {range ? ` · addr ${range[0]}–${range[1]}` : ''}
                    </td>
                  </tr>
                )}
                <tr title={ann?.[2] ?? ''} style={{ borderBottom: '1px solid var(--line)' }}>
                  <td style={{ padding: '3px 8px', color: 'var(--ink-3)' }}>{addr}</td>
                  <td style={{ padding: '3px 8px', color: 'var(--ink)' }}>{ann?.[1] ?? '—'}</td>
                  <td style={{ padding: '3px 8px', color: 'var(--ink-2)' }}>
                    0x{raw.toString(16).toUpperCase().padStart(4, '0')}
                  </td>
                  <td style={{ padding: '3px 8px', color: 'var(--ink)' }}>{signed16(raw)}</td>
                </tr>
              </Fragment>
            );
          })}
        </tbody>
      </table>
    </div>
  );
}
