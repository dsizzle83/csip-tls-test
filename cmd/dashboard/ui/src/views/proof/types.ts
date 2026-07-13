// Wire types for the Proof Center, mirroring the Go structs the dashboard
// backend serves (cmd/dashboard/mayhem.go, qa_reports.go, invariants.go).
// These are the authoritative shapes — field names/tags copied verbatim from
// the JSON tags on those structs. Anything the UI doesn't render is still
// typed so the compiler catches a backend rename.

/** One structured invariant breach (invariants.go invViolation). */
export interface InvViolation {
  inv: string; // "INV-EXPORT" | "INV-SOC" | "INV-CONNECT" | …
  t_s: number; // seconds since scenario start
  detail: string;
}

/** Quantified per-scenario outcome (mayMetrics). */
export interface MayMetrics {
  samples: number;
  sample_errors: number;
  breach_seconds: number;
  peak_breach_W: number;
  recovery_seconds: number; // -1 = n/a or never recovered
  converged_at_s: number; // -1 = never
  tail_clean: boolean;
  breach_converging: boolean;
  hub_adopted: boolean;
  hub_reacted: boolean;
  reported_cannot_comply: boolean;
  hub_blind: boolean;
}

export type Verdict = 'PASS' | 'DEGRADED' | 'FAIL' | 'BLIND' | 'INCONCLUSIVE';

/** Per-scenario verdict + root-cause story (mayFinding). */
export interface MayFinding {
  id: string;
  name: string;
  category: string;
  hypothesis: string;
  expected: string;
  verdict: Verdict;
  headline: string;
  diagnosis: string[];
  fix: string;
  metrics: MayMetrics;
  violations?: InvViolation[]; // safety-audit breaches (CONNECT/SOC/EXPIRED/EVMAX/HUNT)
}

/** Campaign roll-up counts (maySummary). */
export interface MaySummary {
  pass: number;
  degraded: number;
  fail: number;
  blind: number;
  inconclusive: number;
  total_breach_seconds: number;
  worst_peak_breach_W: number;
}

/**
 * One whole-bench observation during the running scenario (maySample). The
 * live[] window is a rolling ~120-sample tail of the scenario in flight.
 */
export interface MaySample {
  t: number; // seconds since scenario start
  real_grid_W: number;
  grid_ok: boolean;
  hub_grid_W: number;

  solar_W: number;
  solar_possible_W: number;
  solar_ok: boolean;
  hub_solar_W: number;

  battery_W: number;
  bat_soc: number;
  battery_sim_W: number;
  battery_sim_soc: number;
  battery_sim_ok: boolean;

  ev_W: number;
  ev_soc: number;
  ev_current_A: number;
  ev_max_current_A: number;
  ev_sim_W: number;
  ev_sim_A: number;
  ev_sim_ok: boolean;

  hub_reachable: boolean;
  hub_adopted: boolean;
  disconnect_active: boolean;
  adopted_typ: string; // exportCap|importCap|genLimit|fixed|connect
  adopted_lim_W: number;
  adopted_mrid: string;
  valid_until: number;
  wall_unix: number;
  clock_offset_s: number;

  cannot_comply: boolean;
  cannot_comply_count: number;
  decisions?: string[];

  meter_stale: boolean;
  ev_stale: boolean;
}

/** GET /api/qa/status (mayhemStatus). */
export interface MayhemStatus {
  running: boolean;
  finished: boolean;
  aborted: boolean;
  last_error?: string;
  started_at: string; // RFC3339
  current: string;
  current_id: string;
  idx: number;
  total: number;
  pct: number;
  phase: string; // setup|hold|recover|done
  chaos_seed?: number;
  report_path?: string;
  summary: MaySummary;
  findings: MayFinding[];
  live: MaySample[];
}

/** One row of GET /api/qa/scenarios (handleScenarios scenarioInfo). */
export interface ScenarioInfo {
  id: string;
  name: string;
  category: string;
  hypothesis: string;
  expected: string;
  extended: boolean;
  source: string; // "go" | "spec"
}

/** POST /api/qa/start body (mayhemStartReq, subset the UI sets). */
export interface StartReq {
  only?: string[];
  sample_ms?: number;
  include_extended?: boolean;
}

/** GET /api/qa/reports row (qaReportEntry). */
export interface QAReportEntry {
  name: string;
  mtime: string; // RFC3339
  bytes: number;
}
