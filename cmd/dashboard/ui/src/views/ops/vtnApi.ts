import { postJSON } from '../../lib/api';

// Thin typed helpers over the OpenADR 3.x VTN admin surface (Phase 3). These
// ride the /api/vtn proxy mount (added alongside this UI — see the dashboard
// backend); until it lands every call resolves against a 404 and the panel
// degrades to its "VTN unreachable" empty state, exactly like the gridsim
// helpers do before their backend is up. The VTN owns a utility-side program +
// event; the lexa-openadr VEN polls it and republishes prices/limits onto the
// hub bus, which is where the "VEN adopted it" proof comes from (status.openadr).

/** One demo program the arm flows upsert-then-reference. Stable id so repeated
 *  arms reuse the same program rather than piling up new ones. */
const PROGRAM_ID = 'lexa-demo';
const PROGRAM_NAME = 'LEXA Demo Program';

export type OpenADRPayloadType = 'PRICE' | 'IMPORT_CAPACITY_LIMIT';

/** The VTN's own admin view (GET /api/vtn/admin/state) — fallback readout when
 *  the hub has not yet surfaced status.openadr. Shape is defensive: the backend
 *  is landing in parallel, so every field is optional. */
export interface VtnAdminState {
  vtn_ok?: boolean;
  programs?: Array<{ id?: string; programName?: string; [k: string]: unknown }>;
  events?: Array<{ id?: string; programID?: string; [k: string]: unknown }>;
  server_time?: number;
  [k: string]: unknown;
}

/**
 * Upsert the demo program so events have something to reference. Idempotent on
 * PROGRAM_ID: the arm flows call this first, then post the event. `payloadType`
 * shapes the descriptor (PRICE carries currency/units; a capacity limit is a
 * bare typed descriptor).
 */
export function upsertOpenADRProgram(payloadType: OpenADRPayloadType = 'PRICE'): Promise<unknown> {
  const descriptor =
    payloadType === 'PRICE'
      ? { payloadType: 'PRICE', currency: 'USD', units: 'KWH' }
      : { payloadType: 'IMPORT_CAPACITY_LIMIT', units: 'W' };
  return postJSON('/api/vtn/admin/programs', {
    id: PROGRAM_ID,
    programName: PROGRAM_NAME,
    payloadDescriptors: [descriptor],
  });
}

/** Build an OpenADR Event with a single now→+duration interval carrying one payload. */
function buildEvent(id: string, type: OpenADRPayloadType, value: number, durationISO: string) {
  return {
    id,
    programID: PROGRAM_ID,
    intervals: [
      {
        payloads: [{ type, values: [value] }],
        intervalPeriod: { start: new Date().toISOString(), duration: durationISO },
      },
    ],
  };
}

/** Arm a PRICE event ($/kWh) at the VTN; the VEN adopts it into the plan's price_forecast. */
export function armOpenADRPrice(id: string, pricePerKwh: number, durationISO = 'PT1H'): Promise<unknown> {
  return postJSON('/api/vtn/admin/events', buildEvent(id, 'PRICE', pricePerKwh, durationISO));
}

/** Arm an IMPORT_CAPACITY_LIMIT event (watts); the VEN adopts it as an enforced import cap (D9). */
export function armOpenADRCap(id: string, watts: number, durationISO = 'PT1H'): Promise<unknown> {
  return postJSON('/api/vtn/admin/events', buildEvent(id, 'IMPORT_CAPACITY_LIMIT', watts, durationISO));
}

/** Cancel a previously-armed event by id. Resolves true on 2xx/204, false otherwise (never throws). */
export async function clearOpenADREvent(id: string): Promise<boolean> {
  try {
    const resp = await fetch('/api/vtn/admin/events', {
      method: 'DELETE',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ id }),
    });
    return resp.ok || resp.status === 204;
  } catch {
    return false;
  }
}
