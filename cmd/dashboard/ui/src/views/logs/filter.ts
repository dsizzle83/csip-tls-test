import type { LogLine } from './types';

/**
 * Text/regex match against one log line. Regex mode compiles `query` as a
 * case-insensitive RegExp; an invalid pattern fails OPEN (matches
 * everything) rather than hiding the whole buffer while the user is mid-edit
 * of a pattern — `regexError` on the same query tells the caller to show a
 * quiet "invalid pattern" hint.
 */
export function matchesQuery(line: string, query: string, regexMode: boolean): boolean {
  if (!query) return true;
  if (!regexMode) return line.toLowerCase().includes(query.toLowerCase());
  try {
    return new RegExp(query, 'i').test(line);
  } catch {
    return true;
  }
}

export function regexError(query: string, regexMode: boolean): string | undefined {
  if (!regexMode || !query) return undefined;
  try {
    new RegExp(query, 'i');
    return undefined;
  } catch (err) {
    return err instanceof Error ? err.message : 'invalid pattern';
  }
}

export function filterLines(
  items: LogLine[],
  enabledSources: ReadonlySet<string>,
  query: string,
  regexMode: boolean
): LogLine[] {
  return items.filter((it) => enabledSources.has(it.src) && matchesQuery(it.line, query, regexMode));
}

/** Buffered count per source (over the *unfiltered* buffer) for the chip counters. */
export function countBySource(items: LogLine[]): Record<string, number> {
  const counts: Record<string, number> = {};
  for (const it of items) counts[it.src] = (counts[it.src] ?? 0) + 1;
  return counts;
}
