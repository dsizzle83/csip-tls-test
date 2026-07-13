// Per-source chip metadata for the /logs view (DESIGN_BRIEF.md §4: "per-source
// color chips (entity colors ONLY for sim sources by role; hub=ink; grid=
// --green-ink)"). Colors are CSS var() references (not lib/colors.ts token()
// lookups) since these only ever land in JSX style props, never a canvas
// context — the browser resolves var() natively and stays in sync with
// theme.css with no JS round-trip.
//
// "meter" has no dedicated slot in the brief's entity table (Solar/Battery/
// Grid/Home load/EV) — it's not a power entity, it's the instrument that
// measures the grid connection, so it wears the Grid entity's color
// (--c-blue). That's deliberately distinct from the "grid" *source* below
// (the gridsim/CSIP protocol log stream), which the brief pins to
// --green-ink — two different things that happen to share the word "grid".
export interface LogSourceMeta {
  id: string;
  label: string;
  /** Protocol badge shown in the chip title, e.g. "IEEE 2030.5". */
  proto: string;
  color: string;
}

export const LOG_SOURCES: LogSourceMeta[] = [
  { id: 'hub', label: 'Hub', proto: 'MQTT/CSIP', color: 'var(--ink)' },
  { id: 'grid', label: 'Grid', proto: 'IEEE 2030.5', color: 'var(--green-ink)' },
  { id: 'solar', label: 'Solar', proto: 'Modbus', color: 'var(--c-amber)' },
  { id: 'battery', label: 'Battery', proto: 'Modbus', color: 'var(--c-green)' },
  { id: 'meter', label: 'Meter', proto: 'Modbus', color: 'var(--c-blue)' },
  { id: 'ev', label: 'EV', proto: 'OCPP', color: 'var(--c-teal)' },
];

const BY_ID = new Map(LOG_SOURCES.map((s) => [s.id, s]));

/** Falls back to a neutral chip for any source id not in the fixed list above. */
export function sourceMeta(id: string): LogSourceMeta {
  return BY_ID.get(id) ?? { id, label: id, proto: '', color: 'var(--ink-3)' };
}
