// Typed fetch helpers for the Savings Studio's three endpoints (CONTRACTS.md
// §3). All go through lib/api's timeout-aware request wrapper.

import { getJSON, postJSON } from '../../lib/api';
import type { Scenario, Tariff, Instruments, Policy, WhatifResponse } from './types';

export function fetchScenarios(): Promise<Scenario[]> {
  return getJSON<Scenario[]>('/api/scenarios');
}

export function fetchTariffs(territory: string): Promise<Tariff[]> {
  return getJSON<Tariff[]>(`/api/tariffs?territory=${encodeURIComponent(territory)}`);
}

export interface RunRequest {
  scenario_id: string;
  tariff_ids: string[];
  instruments?: Instruments;
  policies?: Policy[];
}

export function runWhatif(req: RunRequest): Promise<WhatifResponse> {
  return postJSON<WhatifResponse>('/api/whatif/run', req);
}
