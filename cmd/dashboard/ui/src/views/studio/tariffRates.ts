// Client-side TOU rate lookup for the heatmap. SOURCE OF TRUTH for rate
// semantics is Go internal/tariff/rate.go (periodAt/RateAt) — any change to
// period matching or expandDays there must be mirrored here or the heatmap
// will silently disagree with the server-computed bill.
// Client-side TOU rate lookup for the heatmap (DESIGN_BRIEF.md §4.4: "compute
// client-side from the tariff JSON"). Mirrors internal/tariff RateAt semantics:
// ImportUSDPerKWh = period energy rate + riders, EXCLUDING monthly tier adders
// (those are billing-month state, not an instantaneous rate). Windows resolve
// in local calendar terms (a visual approximation of the tariff timezone — good
// enough for a day×hour heatmap).

import type { Tariff } from './types';

const DOW = ['sun', 'mon', 'tue', 'wed', 'thu', 'fri', 'sat'];

function minutesOf(hhmm: string): number {
  const [h, m] = hhmm.split(':').map(Number);
  return h * 60 + (m || 0);
}

/** Weekday key ("mon".."sun") for an ISO date "YYYY-MM-DD", TZ-stable via UTC. */
export function weekdayKey(dateISO: string): string {
  const [y, mo, d] = dateISO.split('-').map(Number);
  return DOW[new Date(Date.UTC(y, mo - 1, d)).getUTCDay()];
}

function monthOf(dateISO: string): number {
  return Number(dateISO.split('-')[1]);
}

/** True if `mins` falls in [start,end), handling midnight-wrapping periods. */
function inPeriod(mins: number, start: number, end: number): boolean {
  if (end > start) return mins >= start && mins < end;
  // wrap (e.g. 20:00–05:00): covers [start,24:00) ∪ [00:00,end)
  return mins >= start || mins < end;
}

export interface CellRate {
  /** Import $/kWh (energy period rate + riders), excluding tier adders. */
  rate: number;
  /** Human period label, e.g. "High Peak". */
  label: string;
  periodId: string;
}

/** Import rate at a given calendar date + integer hour, or null if uncovered. */
export function importRateAt(
  t: Tariff,
  dateISO: string,
  hour: number
): CellRate | null {
  const month = monthOf(dateISO);
  const wd = weekdayKey(dateISO);
  const season = t.energy.seasons.find((s) => s.months.includes(month));
  if (!season) return null;
  const dayType = season.day_types.find((dt) => dt.days.includes(wd));
  if (!dayType) return null;
  const mins = hour * 60;
  const period = dayType.periods.find((p) =>
    inPeriod(mins, minutesOf(p.start), minutesOf(p.end))
  );
  if (!period) return null;
  const riders = t.riders_usd_per_kwh ?? 0;
  return {
    rate: period.rate_usd_per_kwh + riders,
    label: period.label,
    periodId: period.id,
  };
}
