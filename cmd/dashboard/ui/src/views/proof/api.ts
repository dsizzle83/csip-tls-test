// Typed wrappers around the /api/qa/* surface (cmd/dashboard/mayhem.go +
// qa_reports.go). Thin — the shared lib/api helpers do the fetch/JSON/timeout
// work; these just pin the paths and shapes so the view stays honest about the
// backend contract.

import { getJSON, postJSON } from '../../lib/api';
import type { MayhemStatus, ScenarioInfo, StartReq, QAReportEntry } from './types';

/** Curated scenario catalogue (69 rows). Backend returns {scenarios:[…]}. */
export async function fetchScenarios(signal?: AbortSignal): Promise<ScenarioInfo[]> {
  const res = await getJSON<{ scenarios: ScenarioInfo[] }>('/api/qa/scenarios', { signal });
  return res.scenarios ?? [];
}

/** Poll target — the full live status (findings + rolling live[] window). */
export function fetchStatus(signal?: AbortSignal): Promise<MayhemStatus> {
  return getJSON<MayhemStatus>('/api/qa/status', { signal });
}

/** Kick off a run. 202 Accepted with a small echo body; we only need it not to throw. */
export function startRun(req: StartReq): Promise<unknown> {
  return postJSON<unknown>('/api/qa/start', req);
}

/** Abort the in-flight run (POST, 202). */
export function abortRun(): Promise<unknown> {
  return postJSON<unknown>('/api/qa/abort');
}

/** Saved markdown reports, newest first. */
export function fetchReports(signal?: AbortSignal): Promise<QAReportEntry[]> {
  return getJSON<QAReportEntry[]>('/api/qa/reports', { signal });
}

/** One report's raw markdown (text, not JSON). */
export async function fetchReportMarkdown(name: string, signal?: AbortSignal): Promise<string> {
  const res = await fetch(`/api/qa/reports/${encodeURIComponent(name)}`, { signal });
  if (!res.ok) throw new Error(`report ${name}: ${res.status}`);
  return res.text();
}
