// Types for the LEXA-GW proof tab — a faithful mirror of the /api/gw/* shapes
// in cmd/dashboard/gw.go. Kept thin + honest so the view never invents data.

export interface GwIface {
  id: string;
  label: string;
  dir: 'south' | 'north';
  proto: string;
  secure: boolean;
  up: boolean;
  detail: string;
  metric?: string;
}

export interface GwStatus {
  host: string;
  reachable: boolean;
  interfaces: GwIface[];
  updated_at: string;
}

export interface GwReport {
  id: string;
  desc: string;
  category: string;
  verdict: string; // PASS | FAIL | DEGRADED | BLIND | INCONCLUSIVE
  expected: string[];
  on_pin: boolean; // verdict landed on its expected pin (gate-green)
  security: boolean;
  findings: string[];
  duration_s: number;
}

export interface GwBoard {
  available: boolean;
  source?: string;
  generated_at?: string;
  total: number;
  pass: number;
  fail: number;
  skipped: number;
  gate_green: boolean;
  reports: GwReport[];
}

export interface GwRun {
  mode: 'quick' | 'full';
  state: 'idle' | 'running' | 'done' | 'error';
  started_at?: string;
  error?: string;
  lines: string[];
  board?: GwBoard;
}
