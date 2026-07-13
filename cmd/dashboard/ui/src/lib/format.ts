// Formatters per DESIGN_BRIEF.md §5 ("Voice"): tabular numbers, $ with 2
// decimals under $1000 else whole dollars, en-dash ranges, dates as "Jul 21".
// Every function returns plain text; apply the `.mono`/tabular-nums CSS
// class in the component when the value sits in a data table.

const EN_DASH = '–';

/** Instantaneous power. Auto-scales W -> kW at 1000 W (1 decimal in kW). */
export function formatWatts(watts: number): string {
  if (!Number.isFinite(watts)) return '—';
  const abs = Math.abs(watts);
  if (abs >= 1000) {
    return `${(watts / 1000).toFixed(abs >= 10000 ? 1 : 2)} kW`;
  }
  return `${Math.round(watts)} W`;
}

/** Same scaling as formatWatts but for a bare kW value already in kW. */
export function formatKW(kw: number): string {
  if (!Number.isFinite(kw)) return '—';
  return `${kw.toFixed(Math.abs(kw) >= 10 ? 1 : 2)} kW`;
}

/** Energy. Auto-scales Wh -> kWh at 1000 Wh. */
export function formatWh(wh: number): string {
  if (!Number.isFinite(wh)) return '—';
  const abs = Math.abs(wh);
  if (abs >= 1000) {
    return `${(wh / 1000).toFixed(abs >= 10000 ? 1 : 2)} kWh`;
  }
  return `${Math.round(wh)} Wh`;
}

/** Energy already expressed in kWh. */
export function formatKWh(kwh: number): string {
  if (!Number.isFinite(kwh)) return '—';
  return `${kwh.toFixed(Math.abs(kwh) >= 100 ? 0 : 1)} kWh`;
}

/**
 * Dollar amounts per the brief: 2 decimals under $1000, whole dollars at/above.
 * Negative values render with a leading "-" before the "$" (e.g. -$12.40).
 */
export function formatDollars(amount: number): string {
  if (!Number.isFinite(amount)) return '—';
  const sign = amount < 0 ? '-' : '';
  const abs = Math.abs(amount);
  const opts: Intl.NumberFormatOptions =
    abs < 1000
      ? { minimumFractionDigits: 2, maximumFractionDigits: 2 }
      : { minimumFractionDigits: 0, maximumFractionDigits: 0 };
  return `${sign}$${abs.toLocaleString('en-US', opts)}`;
}

/** Percent with a fixed decimal (default 1), e.g. formatPercent(32.5) -> "32.5%". */
export function formatPercent(pct: number, decimals = 1): string {
  if (!Number.isFinite(pct)) return '—';
  return `${pct.toFixed(decimals)}%`;
}

/** Duration in seconds -> compact "1h 05m" / "5m 12s" / "42s". */
export function formatDuration(seconds: number): string {
  if (!Number.isFinite(seconds)) return '—';
  const s = Math.max(0, Math.round(seconds));
  const h = Math.floor(s / 3600);
  const m = Math.floor((s % 3600) / 60);
  const sec = s % 60;
  if (h > 0) return `${h}h ${String(m).padStart(2, '0')}m`;
  if (m > 0) return `${m}m ${String(sec).padStart(2, '0')}s`;
  return `${sec}s`;
}

/** En-dash range formatter, e.g. formatRange("Jul 3", "Jul 9") -> "Jul 3–Jul 9". */
export function formatRange(a: string, b: string): string {
  return `${a}${EN_DASH}${b}`;
}

/** Dates as "Jul 21" (brief §5). Accepts Date, epoch ms/s, or ISO string. */
export function formatDate(input: Date | number | string): string {
  const d = toDate(input);
  if (!d) return '—';
  return d.toLocaleDateString('en-US', { month: 'short', day: 'numeric' });
}

/** Clock time "14:32:07" (24h, tabular) for live/wall-clock display in the top bar. */
export function formatClock(input: Date | number | string): string {
  const d = toDate(input);
  if (!d) return '—';
  return d.toLocaleTimeString('en-US', {
    hour12: false,
    hour: '2-digit',
    minute: '2-digit',
    second: '2-digit',
  });
}

function toDate(input: Date | number | string): Date | null {
  if (input instanceof Date) return input;
  if (typeof input === 'number') {
    // Heuristic: treat values under 10^12 as epoch seconds, else ms.
    const ms = input < 1e12 ? input * 1000 : input;
    return new Date(ms);
  }
  const d = new Date(input);
  return Number.isNaN(d.getTime()) ? null : d;
}
