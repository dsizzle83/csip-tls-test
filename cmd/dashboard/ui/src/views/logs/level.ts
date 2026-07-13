// Level detection for the /logs view (DESIGN_BRIEF.md §4: "level detection
// (ERROR/WARN highlighting via --s-* text, not fills)"). Word-ish match so
// "errors" and "WARNING" hit but substrings like "terror" or "forwarn" (were
// they ever to appear) don't.

export type LogLevel = 'critical' | 'warn' | 'normal';

const ERROR_RE = /\berror\b/i;
const WARN_RE = /\bwarn(?:ing)?\b/i;

export function detectLevel(line: string): LogLevel {
  if (ERROR_RE.test(line)) return 'critical';
  if (WARN_RE.test(line)) return 'warn';
  return 'normal';
}

/** Text color only — brief is explicit: status colors are never fills on a log row. */
export function levelColor(level: LogLevel): string {
  if (level === 'critical') return 'var(--s-critical)';
  if (level === 'warn') return 'var(--s-warn)';
  return 'var(--ink)';
}
