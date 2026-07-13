// TypeScript shapes for the Savings Studio, typed from the OBSERVED live
// payloads of GET /api/scenarios, GET /api/tariffs, POST /api/whatif/run
// (CONTRACTS.md §3). The UI trusts the wire; Go owns validation.

export type Policy = 'baseline' | 'der_dumb' | 'der_lexa';
export type Confidence = 'filed' | 'published' | 'estimated';

// ── scenario (GET /api/scenarios, and echoed in the run response) ──────────
export interface Location {
  city: string;
  state: string;
  lat: number;
  lon: number;
  timezone: string;
  territory: string;
  blurb: string;
}
export interface Period {
  start: string;
  end: string;
}
export interface WeatherMeta {
  source: string;
  retrieved: string;
  source_url: string;
}
export interface HvacDefaults {
  cool_setpoint_f: number;
  kw_per_degf: number;
  max_kw: number;
}
export interface HomeDefaults {
  profile: string;
  base_kw: number;
  hvac: HvacDefaults;
}
export interface BatteryInstruments {
  kwh: number;
  kw: number;
  reserve_pct: number;
  round_trip_eff: number;
}
export interface EvInstruments {
  present: boolean;
  battery_kwh: number;
  charger_kw: number;
  weekday_kwh: number;
  depart_hour: number;
  return_hour: number;
}
export interface Instruments {
  pv_kw: number;
  battery: BatteryInstruments;
  ev: EvInstruments;
}
export interface Scenario {
  id: string;
  label: string;
  location: Location;
  period: Period;
  weather: WeatherMeta;
  tariff_ids: string[];
  default_tariff_id: string;
  home_defaults: HomeDefaults;
  instrument_defaults: Instruments;
}

// ── tariff (GET /api/tariffs?territory=) ───────────────────────────────────
export interface TariffProvenance {
  source_url: string;
  retrieved: string;
  confidence: Confidence;
  notes?: string;
}
export interface TariffPeriod {
  id: string;
  label: string;
  start: string; // "HH:MM" (may wrap midnight); "24:00" == end of day
  end: string;
  rate_usd_per_kwh: number;
}
export interface TariffDayType {
  days: string[]; // "mon".."sun"
  periods: TariffPeriod[];
}
export interface TariffSeason {
  id: string;
  months: number[]; // 1..12
  day_types: TariffDayType[];
}
export interface TariffTier {
  up_to_kwh: number | null; // null = unbounded
  adder_usd_per_kwh: number;
}
export interface TariffEnergy {
  seasons: TariffSeason[];
  tiers?: TariffTier[];
}
export interface TariffDemand {
  label: string;
  usd_per_kw: number;
  months: number[];
  days: string[];
  start: string;
  end: string;
}
export interface TariffExport {
  type: 'net_metering' | 'buyback' | 'none';
  rate_usd_per_kwh: number;
  monthly_cap?: string;
}
export interface Tariff {
  id: string;
  name: string;
  short_name: string;
  utility: string;
  territory: string;
  timezone: string;
  currency: string;
  effective: { from: string; to: string };
  provenance: TariffProvenance;
  fixed_monthly_usd: number;
  energy: TariffEnergy;
  riders_usd_per_kwh?: number;
  demand?: TariffDemand[];
  export?: TariffExport;
}

// ── whatif run response ────────────────────────────────────────────────────
export interface LineItem {
  kind: string; // fixed | energy | tier_adder | riders | demand | export_credit
  label: string;
  qty: number;
  qty_unit: string;
  rate: number;
  amount_usd: number;
}
export interface Bill {
  line_items: LineItem[];
  total_usd: number;
  credit_carryover_usd?: number; // NEM credits banked toward future months
}
export interface Kpis {
  import_kwh: number;
  export_kwh: number;
  peak_import_kw: number;
  self_consumption_pct: number;
  avg_soc_pct: number;
}
export interface Daily {
  dates: string[];
  cost_usd: number[];
  import_kwh: number[];
  export_kwh: number[];
  pv_kwh: number[];
  load_kwh: number[];
}
export interface DayDetail {
  date: string;
  ticks: number;
  load_kw: number[];
  pv_kw: number[];
  batt_kw: number[]; // + discharge, − charge
  ev_kw: number[];
  grid_kw: number[]; // + import, − export
  soc_pct: number[];
  rate_usd_per_kwh: number[];
}
export interface Run {
  tariff_id: string;
  policy: Policy;
  bill: Bill;
  kpis: Kpis;
  daily: Daily;
  day_detail: DayDetail;
}
export interface SavingsAttribution {
  solar_self_use_usd: number;
  battery_arbitrage_usd: number;
  ev_shift_usd: number;
  demand_usd: number;
  export_usd: number;
}
export interface Savings {
  tariff_id: string;
  vs: string;
  policy: Policy;
  usd: number;
  pct: number;
  attribution: SavingsAttribution;
}
export interface RunProvenanceTariff {
  tariff_id: string;
  name: string;
  source_url: string;
  retrieved: string;
  confidence: Confidence;
  notes: string;
}
export interface RunProvenance {
  weather: string;
  load_model: string;
  tariffs: RunProvenanceTariff[];
  engine: string;
}
export interface WhatifResponse {
  scenario: Scenario;
  runs: Run[];
  savings: Savings[];
  provenance: RunProvenance;
}

// ── selectors ──────────────────────────────────────────────────────────────
export const POLICY_ORDER: Policy[] = ['baseline', 'der_dumb', 'der_lexa'];
export const POLICY_LABEL: Record<Policy, string> = {
  baseline: 'Without LEXA',
  der_dumb: 'DER only',
  der_lexa: 'With LEXA',
};

export function runFor(
  runs: Run[],
  tariffId: string,
  policy: Policy
): Run | undefined {
  return runs.find((r) => r.tariff_id === tariffId && r.policy === policy);
}

export function savingsFor(
  savings: Savings[],
  tariffId: string,
  policy: Policy = 'der_lexa'
): Savings | undefined {
  return savings.find(
    (s) => s.tariff_id === tariffId && s.policy === policy && s.vs === 'baseline'
  );
}
