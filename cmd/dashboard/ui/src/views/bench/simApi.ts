import { postJSON } from '../../lib/api';

// Thin wrappers over the simapi inject/control surface (CONTRACTS.md §6,
// semantics ported from cmd/dashboard/dashboard.html's injectSolar/
// injectBattery/injectMeter/ctrl*/injectEVSOC/injectEVAction — verified
// against the live bench 2026-07-13). Every call resolves to a plain boolean
// so forms can show a quiet ✓/✗ without a try/catch at every call site.

/** POST /api/{sim}/inject — sim-specific field overrides (e.g. {W_W, Conn}). */
export async function simInject(
  sim: 'solar' | 'battery' | 'meter',
  fields: Record<string, number>
): Promise<boolean> {
  if (Object.keys(fields).length === 0) return false;
  try {
    await postJSON(`/api/${sim}/inject`, fields);
    return true;
  } catch {
    return false;
  }
}

/**
 * POST /api/{sim}/control — {cmd, speed?}. `speed` is applied independently
 * of `cmd` by every sim backend (simapi.ControlCmd), so a speed-only change
 * still needs *some* cmd; callers pass 'resume' for that case exactly like
 * the legacy ctrlSolarSpeed/ctrlBatterySpeed helpers did.
 */
export async function simControl(
  sim: 'solar' | 'battery' | 'meter',
  cmd: string,
  speed?: number
): Promise<boolean> {
  try {
    const body: { cmd: string; speed?: number } = { cmd };
    if (speed !== undefined && Number.isFinite(speed) && speed > 0) body.speed = speed;
    await postJSON(`/api/${sim}/control`, body);
    return true;
  } catch {
    return false;
  }
}

/** POST /api/ev/inject — {action: 'set_soc', soc_pct} or {action, connector_id}. */
export async function evInject(action: string, extra?: Record<string, unknown>): Promise<boolean> {
  try {
    await postJSON('/api/ev/inject', { action, ...extra });
    return true;
  } catch {
    return false;
  }
}
