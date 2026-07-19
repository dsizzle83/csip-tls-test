// Typed wrappers around the /api/gw/* surface (cmd/dashboard/gw.go). Thin — the
// shared lib/api helpers do the fetch/JSON/timeout work; these pin the paths.

import { getJSON, postJSON } from '../../lib/api';
import type { GwStatus, GwBoard, GwRun } from './types';

/** Live 4-interface topology + gateway reachability + DER telemetry. */
export function fetchGwStatus(signal?: AbortSignal): Promise<GwStatus> {
  return getJSON<GwStatus>('/api/gw/status', { signal });
}

/** The newest gw-mayhem adversarial-QA verdict board (the saved proof). */
export function fetchGwReport(signal?: AbortSignal): Promise<GwBoard> {
  return getJSON<GwBoard>('/api/gw/qa/report', { signal });
}

/** Kick off a live gw-mayhem run through the isolation wrapper. 202 Accepted. */
export function startGwRun(mode: 'quick' | 'full'): Promise<unknown> {
  return postJSON<unknown>('/api/gw/qa/run', { mode });
}

/** Poll the in-flight (or last) live run. state:"idle" before the first run. */
export function fetchGwRunStatus(signal?: AbortSignal): Promise<GwRun> {
  return getJSON<GwRun>('/api/gw/qa/run/status', { signal });
}
