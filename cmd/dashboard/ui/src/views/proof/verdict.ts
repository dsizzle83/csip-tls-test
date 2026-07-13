// Verdict + invariant vocabulary for the Proof Center. Verdict colors come
// straight from STATUS_COLORS (DESIGN_BRIEF.md §1) — status colors are used
// ONLY for status here, and always paired with an icon + label (never color
// alone). The invariant one-liners are written from the header comments in
// cmd/dashboard/invariants.go.

import { token } from '../../lib/colors';
import type { MayFinding, Verdict } from './types';

export interface VerdictMeta {
  icon: string;
  label: string;
  cssVar: string; // for CSS var() text/border
}

// Icons per the task: ✓ ◐ ⚠ ✕ ?
export const VERDICT_META: Record<Verdict, VerdictMeta> = {
  PASS: { icon: '✓', label: 'Pass', cssVar: '--s-good' },
  DEGRADED: { icon: '◐', label: 'Degraded', cssVar: '--s-warn' },
  BLIND: { icon: '⚠', label: 'Blind', cssVar: '--s-serious' },
  FAIL: { icon: '✕', label: 'Fail', cssVar: '--s-critical' },
  INCONCLUSIVE: { icon: '?', label: 'Inconclusive', cssVar: '--s-neutral' },
};

export function verdictMeta(v: string): VerdictMeta {
  return VERDICT_META[(v as Verdict)] ?? VERDICT_META.INCONCLUSIVE;
}

/** Resolved hex for a verdict (for ECharts marks). */
export function verdictColor(v: string): string {
  return token(verdictMeta(v).cssVar);
}

// Ordered worst-first so we can pick the most severe verdict in a set.
const SEVERITY: Verdict[] = ['FAIL', 'BLIND', 'DEGRADED', 'INCONCLUSIVE', 'PASS'];

export function worstVerdict(a: string | null, b: string): string {
  if (!a) return b;
  return SEVERITY.indexOf(a as Verdict) <= SEVERITY.indexOf(b as Verdict) ? a : b;
}

// ── Safety invariants ────────────────────────────────────────────────────────

export interface InvariantDef {
  id: string;
  short: string; // headline chip label, e.g. "No back-feed"
  line: string; // plain-language one-liner (from invariants.go)
  /**
   * How this invariant is judged from a finding. "audit" invariants appear
   * directly in finding.violations[] (safetyAudit runs them on EVERY
   * scenario). "oracle" invariants (EXPORT/CONVERGE) are a scenario's primary
   * oracle and are NOT in violations[] — a breach surfaces as a FAIL/BLIND
   * verdict on a scenario that names the invariant. See invariants.go
   * safetyAudit(): it deliberately excludes INV-EXPORT/INV-CONVERGE.
   */
  kind: 'audit' | 'oracle';
}

// The four headline cards (brief §4) + the compact row (EVMAX/HUNT/CONVERGE).
export const HEADLINE_INVARIANTS: InvariantDef[] = [
  {
    id: 'INV-SOC',
    short: 'Battery bounds held',
    line: 'A charge that would push the battery past full, or a discharge below its reserve floor, is never carried out — even when a command’s sign is flipped.',
    kind: 'audit',
  },
  {
    id: 'INV-CONNECT',
    short: 'No back-feed',
    line: 'During a grid-disconnect order, the system never back-feeds the grid — all controllable generation and discharge is driven to zero.',
    kind: 'audit',
  },
  {
    id: 'INV-EXPORT',
    short: 'Export cap held',
    line: 'Solar and battery export never exceeds the grid operator’s active cap once the system has been given time to settle.',
    kind: 'oracle',
  },
  {
    id: 'INV-EXPIRED',
    short: 'No stale authority',
    line: 'The system stops enforcing a grid control the moment its authorization expires — it never acts on authority the operator has withdrawn.',
    kind: 'audit',
  },
];

export const COMPACT_INVARIANTS: InvariantDef[] = [
  {
    id: 'INV-EVMAX',
    short: 'EV within station max',
    line: 'The EV charger never draws more current than its station’s hardware maximum.',
    kind: 'audit',
  },
  {
    id: 'INV-HUNT',
    short: 'No oscillation',
    line: 'The control loop settles below the cap and holds — it never oscillates curtail→release→breach in a way that grinds hardware.',
    kind: 'audit',
  },
  {
    id: 'INV-CONVERGE',
    short: 'Honest limits',
    line: 'A commanded limit that measurement never reaches is always admitted (CannotComply) — the hub never silently trusts a device’s ACK.',
    kind: 'oracle',
  },
];

export const ALL_INVARIANTS: InvariantDef[] = [...HEADLINE_INVARIANTS, ...COMPACT_INVARIANTS];

export type InvState =
  | { state: 'idle' } // no run this session, or this invariant untouched by the run
  | { state: 'held'; scenarios: number }
  | { state: 'violated'; verdict: string; byId: string; scenarios: number };

/** Does a finding exercise this oracle invariant (name appears in its metadata)? */
function mentions(f: MayFinding, invId: string): boolean {
  const hay = `${f.id} ${f.category} ${f.expected} ${f.hypothesis}`.toUpperCase();
  return hay.includes(invId.toUpperCase());
}

/**
 * Derive an invariant's status from a run's findings. Honest, non-faked:
 *  - audit invariants: guarded on EVERY scenario (safetyAudit runs them all),
 *    so scenarios == findings.length; violated iff any finding.violations names it.
 *  - oracle invariants (EXPORT/CONVERGE): only scenarios that name the invariant
 *    exercise it; violated iff such a scenario reached FAIL or BLIND.
 * With no findings (no run this session) the invariant is 'idle'.
 */
export function invStatus(def: InvariantDef, findings: MayFinding[]): InvState {
  if (findings.length === 0) return { state: 'idle' };
  let touched = 0;
  let worst: string | null = null;
  let worstId = '';
  for (const f of findings) {
    const touches = def.kind === 'audit' ? true : mentions(f, def.id);
    if (!touches) continue;
    touched++;
    const violated =
      def.kind === 'audit'
        ? (f.violations ?? []).some((v) => v.inv === def.id)
        : f.verdict === 'FAIL' || f.verdict === 'BLIND';
    if (violated) {
      const w = worstVerdict(worst, f.verdict);
      if (w !== worst) {
        worst = w;
        worstId = f.id;
      }
    }
  }
  if (touched === 0) return { state: 'idle' };
  if (worst) return { state: 'violated', verdict: worst, byId: worstId, scenarios: touched };
  return { state: 'held', scenarios: touched };
}

// ── Run presets (brief §4 / task) ────────────────────────────────────────────

/** Quick sweep — 7 fast, well-known scenarios. */
export const QUICK_SWEEP_IDS = [
  'export-cap-full-battery',
  'ack-before-effect',
  'stale-meter',
  'battery-empty-import-cap',
  'curtailment-release',
  'clock-jitter',
  'perfect-storm',
];
