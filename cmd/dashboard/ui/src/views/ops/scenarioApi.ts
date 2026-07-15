import { postJSON } from '../../lib/api';
import { simInject } from '../bench/simApi';
import type { DerBase } from './types';

// Thin typed helpers over EXISTING bench endpoints for the Injection Console —
// no new proxy mounts. Grid controls travel the same program-0 /admin/control
// path the Grid Event Console uses (the CSIP "watch the hub enforce" story);
// weather and load are sim injects via the shared simApi surface.

const PROGRAM = 0;

export interface GridControlResp {
  mrid: string;
}

/**
 * POST a DERControl (program 0, activate) to the live gridsim and return the
 * assigned mRID — the handle the lifecycle tracker matches against the hub's
 * adopted control. `base` carries whichever single limit the scenario drives
 * (e.g. { gen_lim_W } or { imp_lim_W }).
 */
export function fireGridControl(base: DerBase, durationS: number, description = 'Injection Console'): Promise<GridControlResp> {
  return postJSON<GridControlResp>('/api/gridsim/admin/control', {
    program: PROGRAM,
    activate: true,
    duration_s: durationS,
    description,
    ...base,
  });
}

/** DELETE every control on program 0 — reverts the grid to its default control. */
export async function clearGridControl(): Promise<boolean> {
  try {
    const resp = await fetch('/api/gridsim/admin/control', {
      method: 'DELETE',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ program: PROGRAM }),
    });
    return resp.ok || resp.status === 204;
  } catch {
    return false;
  }
}

/** Roll clouds over the array (0 = clear, 100 = overcast). Solar sim inject. */
export function setCloud(pct: number): Promise<boolean> {
  return simInject('solar', { Cloud_pct: pct });
}

/** Direct inverter curtailment ceiling (0–100 %). 100 releases the cap. */
export function curtailInverter(pct: number): Promise<boolean> {
  return simInject('solar', { WMaxLimPct_pct: pct });
}

/** Pin the house load to a fixed surge (W) — meter sim, linked-load setpoint. */
export function spikeHomeLoad(watts: number): Promise<boolean> {
  return simInject('meter', { LoadW_W: watts });
}

/** Release the pinned load and resume the diurnal curve at this mean (W). */
export function resumeHomeLoad(meanW: number): Promise<boolean> {
  return simInject('meter', { LoadAvgW_W: meanW });
}
