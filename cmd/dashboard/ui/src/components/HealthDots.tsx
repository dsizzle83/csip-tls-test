import { usePoll } from '../lib/usePoll';
import { probeHealth } from '../lib/api';

interface HealthTarget {
  id: string;
  label: string;
  path: string;
}

// Lightweight probe targets for the top-bar dot row (brief §3: "hub,
// gridsim, 4 sims"). Kept here (not lib/) since the target list is a shell
// concern, not shared infrastructure.
const TARGETS: HealthTarget[] = [
  { id: 'hub', label: 'Hub', path: '/api/hub/healthz' },
  { id: 'gridsim', label: 'Gridsim', path: '/api/gridsim/admin/status' },
  { id: 'solar', label: 'Solar', path: '/api/solar/state' },
  { id: 'battery', label: 'Battery', path: '/api/battery/state' },
  { id: 'meter', label: 'Meter', path: '/api/meter/state' },
  { id: 'ev', label: 'EV', path: '/api/ev/state' },
];

const PROBE_TIMEOUT_MS = 2000;
const POLL_INTERVAL_MS = 5000;

type Statuses = Record<string, boolean>;

async function probeAll(): Promise<Statuses> {
  const results = await Promise.all(
    TARGETS.map(async (t) => [t.id, await probeHealth(t.path, PROBE_TIMEOUT_MS)] as const)
  );
  return Object.fromEntries(results);
}

/**
 * Bench health dot-row (top bar, right side, brief §3): one 8px dot per
 * target, green on 2xx / red otherwise, tooltip names it. Polls every 5s via
 * usePoll (which itself pauses while the tab is hidden).
 */
export function HealthDots() {
  const { data: statuses } = usePoll<Statuses>(probeAll, POLL_INTERVAL_MS);

  return (
    <div className="health-dots" role="list" aria-label="Bench health">
      {TARGETS.map((t) => {
        const ok = statuses?.[t.id];
        const state = ok === undefined ? 'checking…' : ok ? 'healthy' : 'unreachable';
        return (
          <span
            key={t.id}
            role="listitem"
            title={`${t.label}: ${state}`}
            className="health-dot"
            style={{
              background:
                ok === undefined ? 'var(--ink-3)' : ok ? 'var(--s-good)' : 'var(--s-critical)',
            }}
          />
        );
      })}
    </div>
  );
}
