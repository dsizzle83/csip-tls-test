// Types for the /ops Live Ops view, hand-typed from OBSERVED live payloads on
// the real bench (2026-07-13) — not from a schema. Fields are optional wherever
// the hub omits them before the first plan (503) or when a device is absent, so
// every panel can render a quiet empty state. Sources:
//   GET /api/hub/status            (1 s poll — the live spine of this view)
//   GET /api/hub/plan              (24 h forecast; 30 s poll)
//   GET /api/gridsim/admin/status  (advertised CSIP programs/controls)
//   GET /api/gridsim/admin/tariff  (ships later tonight — 404 today)
//   POST/DELETE /api/gridsim/admin/control  (grid event console; body = admin.go adminCtrlReq)

// ── /api/hub/status ────────────────────────────────────────────────────────

export interface HubDevice {
  role: string; // "battery" | "inverter" | "meter" | …
  W_W: number;
  V_V?: number;
  Hz_Hz?: number;
  soc_pct?: number;
  max_W?: number;
  connected: boolean;
}

export interface PowerSnapshot {
  solar_W: number;
  battery_W: number; // >0 discharge (source), <0 charge (sink)
  grid_W: number; // >0 import (source), <0 export (sink) — "meter import positive"
  load_W: number; // = solar + battery + grid − ev  (verified against live data)
}

export interface HubDecision {
  rule: string;
  reason: string;
  impact: string;
}

/** DERControlBase as the hub/gridsim expose it: only present limits are set. */
export interface DerBase {
  exp_lim_W?: number;
  max_lim_W?: number;
  imp_lim_W?: number;
  gen_lim_W?: number;
  load_lim_W?: number;
  fixed_W?: number;
  connect?: boolean;
  energize?: boolean;
  fixed_pf_inject_pct?: number;
  fixed_pf_absorb_pct?: number;
  fixed_var_pct?: number;
  /** Curve-linked mode when a DER function curve is bound to this control
   *  (Phase 3 — populated by gridsim once the curve backend lands; absent
   *  today). Rendered next to var% in the Protocol Inspector. */
  curve_mode?: CurveMode | string;
}

export interface CsipControl {
  source: string; // "default" | "event"
  mrid: string;
  valid_until?: number; // epoch seconds (absent on the default control — no expiry)
  base: DerBase;
}

export interface EvseStation {
  station_id: string;
  connector_id: number;
  connected: boolean;
  session_active: boolean;
  status: string; // "Occupied" | "Available" | …
  power_W: number;
  soc_pct?: number;
  energy_Wh?: number;
  max_current_A?: number;
  current_A?: number;
}

export interface HubStatus {
  timestamp: string; // ISO
  clock_offset_s?: number;
  csip_programs?: number;
  csip_control?: CsipControl;
  devices?: Record<string, HubDevice>;
  power?: PowerSnapshot;
  last_plan?: { timestamp: string; decisions: HubDecision[] };
  evse_stations?: EvseStation[];
  plan_heartbeat?: { state: string; age_s: number };
  mode?: string; // "gateway" | …
  /** Present only when a source is stale; absent when all fresh (task spec). */
  stale_sources?: string[];
  reserve?: { effective_pct: number; floor_pct: number; source: string };
  tariff?: { source: string; updated_at: number };
  fw?: string;
  /** OpenADR VEN health (Phase 3, WP-15) — added to /status by lexa-api.
   *  OPTIONAL: the UI renders (with a VTN-unreachable fallback) before this
   *  field ships, and reads the VTN's own /admin/state as a backstop. */
  openadr?: OpenADRHealth;
}

// ── OpenADR VEN health (status.openadr) ─────────────────────────────────────

export interface OpenADRHealth {
  vtn_ok?: boolean;
  token_ok?: boolean;
  last_poll_ts?: number; // epoch seconds of the VEN's last successful VTN poll
  programs?: number;
  active_events?: number;
  last_err?: string;
}

// ── DER function curves (Phase 3) ───────────────────────────────────────────

/** The four DER autonomous-function curve modes the demo can activate. Maps to
 *  SunSpec models 705 (Volt-VAr) / 706 (Volt-Watt) / 711 (Freq-Watt) / 712 (Watt-PF). */
export type CurveMode = 'volt_var' | 'volt_watt' | 'freq_watt' | 'watt_pf';

/** One curve point as the gridsim /admin/curve POST body carries it ({x,y}).
 *  Note the advanced-solar readback (GET /api/solar/state) uses [x,y] tuples. */
export interface CurvePoint {
  x: number;
  y: number;
}

/** POST /api/gridsim/admin/curve body (Phase 3 — the curve backend consumes it). */
export interface AdminCurveReq {
  program: number;
  mode: CurveMode;
  points: CurvePoint[];
  vref?: number;
  duration_s?: number;
  activate?: boolean;
}

/** A curve as gridsim may advertise it back on /admin/status once bound
 *  (optional — absent until the backend lands; the console falls back to the
 *  locally-issued curve). */
export interface AdvertisedCurve {
  mode?: CurveMode | string;
  vref?: number;
  points?: [number, number][];
  duration_s?: number;
}

// ── /api/hub/plan ──────────────────────────────────────────────────────────

export interface SolarForecastPoint { t: string; solar_W: number; }
/** Home consumption forecast (NEW — the hub may emit `load_forecast: []` before
 *  it has a load model; consumers must render gracefully when it is empty). */
export interface LoadForecastPoint { t: string; load_W: number; }
export interface BatteryPlanPoint { t: string; setpoint_W: number; soc_pct: number | null; }
export interface CostPlanPoint { t: string; grid_W: number; marginal_cost: number; }
export interface PriceForecastPoint {
  t: string;
  import_per_kwh: number;
  delivery_per_kwh: number;
  export_per_kwh: number;
}

export interface HubPlan {
  generated_at: string;
  horizon_h: number;
  slot_minutes: number;
  currency: string;
  total_cost: number;
  fixed_daily_charge?: number;
  solar_forecast: SolarForecastPoint[];
  /** Home consumption forecast — may be [] on a hub that predates the field. */
  load_forecast?: LoadForecastPoint[];
  battery_plan: BatteryPlanPoint[];
  cost_plan: CostPlanPoint[];
  price_forecast: PriceForecastPoint[];
  ev_plan?: Record<string, { t: string; power_W: number }[]>;
}

// ── /api/gridsim/admin/status ──────────────────────────────────────────────

export interface AdminCtrl {
  mrid: string;
  description: string;
  start: number; // epoch seconds (server/skewed time)
  duration_s: number;
  status: number; // 0 Scheduled, 1 Active (IEEE 2030.5 event state)
  base: DerBase;
}

export interface AdminProgram {
  id: number;
  mrid: string;
  description: string;
  primacy: number;
  default?: DerBase;
  active: AdminCtrl[] | null;
  scheduled: AdminCtrl[] | null;
  /** Bound DER function curve, once gridsim advertises it (Phase 3; optional). */
  curve?: AdvertisedCurve;
}

export interface AdminStatus {
  programs: AdminProgram[];
  server_time: number;
}

// ── /api/gridsim/admin/tariff (defensive — shape unknown, endpoint pending) ──

export interface TariffInterval {
  start?: number;
  duration_s?: number;
  import_per_kwh?: number;
  export_per_kwh?: number;
  price?: number;
  [k: string]: unknown;
}

export interface TariffResp {
  intervals?: TariffInterval[];
  [k: string]: unknown;
}

// ── /api/gridsim/admin/control POST body (mirrors gridsim adminCtrlReq) ─────

export interface AdminCtrlReq {
  program: number;
  description?: string;
  start_offset_s?: number;
  duration_s?: number;
  activate?: boolean;
  exp_lim_W?: number;
  max_lim_W?: number;
  imp_lim_W?: number;
  gen_lim_W?: number;
  load_lim_W?: number;
  fixed_W?: number;
  connect?: boolean;
  energize?: boolean;
}
