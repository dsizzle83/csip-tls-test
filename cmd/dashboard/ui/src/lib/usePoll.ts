import { useEffect, useRef, useState } from 'react';

export interface UsePollResult<T> {
  data: T | undefined;
  error: unknown;
  /** True while the very first fetch is in flight. */
  loading: boolean;
  /** Force an immediate re-fetch outside the interval (e.g. after a user action). */
  refresh: () => void;
}

/**
 * Polls `fn` every `intervalMs`, pausing while the tab is hidden
 * (visibilitychange) and firing an immediate refresh on becoming visible
 * again so views don't show stale data after a tab switch. Cadences per
 * CONTRACTS.md §6: hub status 1000, qa status 1500, replay 3000, health
 * dots 5000.
 *
 * Usage:
 *   const { data, error, loading } = usePoll(() => getJSON<HubStatus>('/api/hub/status'), 1000);
 */
export function usePoll<T>(
  fn: () => Promise<T>,
  intervalMs: number,
  deps: React.DependencyList = []
): UsePollResult<T> {
  const [data, setData] = useState<T | undefined>(undefined);
  const [error, setError] = useState<unknown>(undefined);
  const [loading, setLoading] = useState(true);
  const fnRef = useRef(fn);
  fnRef.current = fn;
  const tickRef = useRef(0);
  const lastJSONRef = useRef<string | undefined>(undefined);

  // Keep the previous object identity when the payload is byte-identical:
  // most 1s polls of an idle bench return the same JSON, and a fresh object
  // every tick would re-render every consumer and re-fire every
  // useMemo/EChart setOption for identical pixels.
  const setDataIfChanged = (result: T) => {
    let key: string | undefined;
    try {
      key = JSON.stringify(result);
    } catch {
      key = undefined; // non-serializable — always treat as changed
    }
    if (key === undefined || key !== lastJSONRef.current) {
      lastJSONRef.current = key;
      setData(result);
    }
  };

  // eslint-disable-next-line react-hooks/exhaustive-deps
  useEffect(() => {
    let cancelled = false;
    let timer: ReturnType<typeof setTimeout> | undefined;
    setLoading(true);

    const run = async () => {
      const myTick = ++tickRef.current;
      try {
        const result = await fnRef.current();
        if (cancelled || myTick !== tickRef.current) return;
        setDataIfChanged(result);
        setError(undefined);
      } catch (err) {
        if (cancelled || myTick !== tickRef.current) return;
        setError(err);
      } finally {
        if (!cancelled) setLoading(false);
      }
    };

    const schedule = () => {
      timer = setTimeout(async () => {
        if (document.visibilityState === 'visible') {
          await run();
        }
        if (!cancelled) schedule();
      }, intervalMs);
    };

    const onVisibility = () => {
      if (document.visibilityState === 'visible') {
        // Refresh immediately on returning to the tab rather than waiting
        // out the rest of the interval.
        run();
      }
    };

    run();
    schedule();
    document.addEventListener('visibilitychange', onVisibility);

    return () => {
      cancelled = true;
      if (timer) clearTimeout(timer);
      document.removeEventListener('visibilitychange', onVisibility);
    };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [intervalMs, ...deps]);

  const refresh = () => {
    tickRef.current++; // invalidate any in-flight interval tick's result
    setLoading(true);
    fnRef
      .current()
      .then((result) => {
        setDataIfChanged(result);
        setError(undefined);
      })
      .catch((err) => setError(err))
      .finally(() => setLoading(false));
  };

  return { data, error, loading, refresh };
}
