import { useCallback, useEffect, useRef, useState } from 'react';
import type { DerBase, HubStatus } from './types';
import { evalLimit, serverNowS } from './util';

// Lifecycle tracker for a fired DERControl: issued → adopted (hub mRID match) →
// compliant (meter inside limit+150 W for HOLD_N consecutive polls) → released,
// with the measured Δt at each hop and a settle verdict. Extracted verbatim from
// EventConsole so the Injection Console can reuse the exact same "watch it land"
// machinery. The advancement logic is driven by the parent's 1 s status poll and
// is intentionally identical to the original inline tracker (behavior-preserving).

export type EventKind = 'export' | 'import' | 'gen' | 'load' | 'fixed' | 'cease';
export type Verdict = 'pass' | 'released' | 'expired' | 'adopted' | 'never-adopted';

const HOLD_N = 3; // consecutive compliant polls (legacy condMet semantics)
const ADOPT_TIMEOUT_MS = 20000;

export const KIND_LABEL: Record<EventKind, string> = {
  export: 'Export cap',
  import: 'Import cap',
  gen: 'Gen limit',
  load: 'Load limit',
  fixed: 'Fixed W',
  cease: 'Cease energize',
};

export interface TrackedEvent {
  id: number;
  label: string;
  kind: EventKind;
  base: DerBase;
  mrid?: string;
  t0: number;
  adoptedAt?: number;
  compliantAt?: number;
  releasedAt?: number;
  validUntil?: number;
  holdCount: number;
  settled: boolean;
  verdict?: Verdict;
  error?: string;
}

export interface TrackInput {
  label: string;
  kind: EventKind;
  base: DerBase;
  mrid?: string;
}

export interface EventTracker {
  events: TrackedEvent[];
  /** Begin tracking a freshly-issued control; returns its local id (newest first). */
  track(input: TrackInput): number;
  /** Attach the gridsim-assigned mRID once the POST resolves. */
  attachMrid(id: number, mrid: string): void;
  /** Force-settle one event (POST failure, manual clear). */
  settle(id: number, verdict: Verdict, error?: string): void;
  /** Settle every still-tracking event (Clear controls / Restore bench). */
  settleAll(verdictFor?: (e: TrackedEvent) => Verdict): void;
}

export function useEventTracker(status: HubStatus | undefined, cap = 12): EventTracker {
  const [events, setEvents] = useState<TrackedEvent[]>([]);
  const idRef = useRef(0);

  // Lifecycle tracker — driven by the parent's 1 s status poll. The early-out
  // when everything is settled keeps object identity stable (no idle re-renders).
  useEffect(() => {
    if (!status) return;
    setEvents((prev) => {
      if (!prev.some((e) => !e.settled)) return prev;
      let changed = false;
      const nowMs = Date.now();
      const csip = status.csip_control;
      const snow = serverNowS(status);
      const next = prev.map((ev) => {
        if (ev.settled) return ev;
        let e = ev;
        const patch = (p: Partial<TrackedEvent>) => {
          e = { ...e, ...p };
          changed = true;
        };

        // never adopted → give up after a timeout
        if (!e.adoptedAt && nowMs - e.t0 > ADOPT_TIMEOUT_MS) {
          patch({ settled: true, verdict: 'never-adopted', releasedAt: nowMs });
          return e;
        }
        // adoption: hub reports our mRID
        if (!e.adoptedAt && e.mrid && csip?.mrid === e.mrid) {
          patch({ adoptedAt: nowMs, validUntil: csip.valid_until, ...(e.kind === 'cease' ? { compliantAt: nowMs } : {}) });
        }
        // compliance: meter inside limit+tol for HOLD_N consecutive polls
        if (e.adoptedAt && !e.compliantAt && e.kind !== 'cease') {
          const le = evalLimit(e.base, status.power);
          if (le) {
            const hc = le.within ? e.holdCount + 1 : 0;
            if (hc >= HOLD_N) patch({ compliantAt: nowMs, holdCount: hc });
            else patch({ holdCount: hc });
          }
        }
        // release: hub moved off our control, or the window expired
        if (e.adoptedAt && csip && csip.mrid !== e.mrid) {
          patch({ releasedAt: nowMs, settled: true, verdict: e.kind === 'cease' ? 'adopted' : e.compliantAt ? 'pass' : 'released' });
        } else if (e.adoptedAt && !e.settled && e.validUntil && snow >= e.validUntil) {
          patch({ releasedAt: nowMs, settled: true, verdict: e.kind === 'cease' ? 'adopted' : e.compliantAt ? 'pass' : 'expired' });
        }
        return e;
      });
      return changed ? next : prev;
    });
  }, [status]);

  const track = useCallback(
    (input: TrackInput) => {
      const id = idRef.current++;
      const t0 = Date.now();
      setEvents((prev) => [{ id, t0, holdCount: 0, settled: false, ...input }, ...prev].slice(0, cap));
      return id;
    },
    [cap]
  );

  const attachMrid = useCallback((id: number, mrid: string) => {
    setEvents((prev) => prev.map((e) => (e.id === id ? { ...e, mrid } : e)));
  }, []);

  const settle = useCallback((id: number, verdict: Verdict, error?: string) => {
    setEvents((prev) =>
      prev.map((e) => (e.id === id && !e.settled ? { ...e, settled: true, verdict, error, releasedAt: e.releasedAt ?? Date.now() } : e))
    );
  }, []);

  const settleAll = useCallback((verdictFor?: (e: TrackedEvent) => Verdict) => {
    const nowMs = Date.now();
    setEvents((prev) =>
      prev.map((e) => (e.settled ? e : { ...e, settled: true, releasedAt: nowMs, verdict: verdictFor ? verdictFor(e) : e.compliantAt ? 'pass' : 'released' }))
    );
  }, []);

  return { events, track, attachMrid, settle, settleAll };
}
