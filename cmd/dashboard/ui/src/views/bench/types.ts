// Wire shapes observed live from simapi (GET /api/{solar,battery,meter,ev}/state,
// 2026-07-13 against the real bench, cross-checked with CONTRACTS.md §6 and
// the legacy dashboard.html telemetry renderers). These are read-only DTOs —
// no validation, the Go side owns that; the UI trusts the wire per CONTRACTS.md §7.

export interface SimAnimation {
  paused: boolean;
  speed: number;
}

export interface SolarState {
  type: string;
  timestamp: string;
  animation: SimAnimation;
  nameplate: { wmax_W: number };
  measurements: {
    W_W: number;
    possible_W: number;
    V_V: number;
    Hz_Hz: number;
    VA_VA: number;
    VAr_var: number;
    PF: number;
    DCV_V: number;
    DCW_W: number;
    TmpCab_C: number;
    St: number;
    St_text: string;
  };
  controls: { WMaxLimPct_pct: number; WMaxLimPct_Ena: number; Conn: number };
}

export interface BatteryState {
  type: string;
  timestamp: string;
  animation: SimAnimation;
  nameplate: { wmax_W: number; capacity_Wh: number };
  measurements: {
    W_W: number;
    V_V: number;
    Hz_Hz: number;
    TmpCab_C: number;
    St: number;
    St_text: string;
  };
  battery: { SoC_pct: number; DoD_pct: number; SoH_pct: number; ChaSt: number; ChaSt_text: string };
  controls: { WMaxLimPct_pct: number; Conn: number };
}

export interface MeterState {
  type: string;
  timestamp: string;
  measurements: {
    W_W: number;
    V_V: number;
    Hz_Hz: number;
    VA_VA: number;
    PF: number;
    A_A: number;
    TotWhImp_Wh: number;
    TotWhExp_Wh: number;
  };
  energy_balance: { load_W: number; source_solar_W: number; source_battery_W: number; load_ev_W: number };
}

export interface EVConnector {
  id: number;
  status: string;
  last_update: string;
}

export interface EVChargingProfile {
  received_at: string;
  evse_id: number;
  profile_id: number;
  purpose: string;
  limit_A: number;
}

export interface EVState {
  type: string;
  timestamp: string;
  station_id: string;
  csms: { url: string; connected: boolean };
  connectors: EVConnector[];
  session: {
    active: boolean;
    connector_id?: number;
    started_at?: string;
    transaction_id?: string;
  };
  battery: {
    capacity_Wh: number;
    soc_pct: number;
    current_A: number;
    power_W: number;
    session_energy_Wh: number;
    phase: string;
  };
  last_heartbeat?: string;
  last_charging_profile?: EVChargingProfile;
}

/** GET /api/{solar,battery}/registers: address (string key) -> raw uint16 value. */
export type RegisterMap = Record<string, number>;
