import { useEffect, useRef, useState } from 'react';

export interface UseSSEOptions<T> {
  /** Parse a raw SSE message into T. Default: JSON.parse(event.data). */
  parse?: (event: MessageEvent) => T;
  /** Max items kept in the ring buffer (oldest dropped first). Default 1000. */
  maxBufferSize?: number;
  /** Base reconnect delay in ms; backs off exponentially up to maxReconnectDelayMs. Default 1000. */
  reconnectDelayMs?: number;
  /** Cap on the backoff. Default 15000. */
  maxReconnectDelayMs?: number;
  /** Named SSE event to listen on instead of the default "message". */
  eventName?: string;
  /** Set false to tear the connection down without unmounting (e.g. paused logs view). */
  enabled?: boolean;
}

export interface UseSSEResult<T> {
  /** Ring buffer contents, oldest first, capped at maxBufferSize. */
  items: T[];
  connected: boolean;
  error: unknown;
  /** Empty the ring buffer without touching the connection. */
  clear: () => void;
}

const DEFAULT_MAX_BUFFER = 1000;
const DEFAULT_RECONNECT_MS = 1000;
const DEFAULT_MAX_RECONNECT_MS = 15000;

/**
 * Subscribes to an SSE endpoint (e.g. `/api/logs/all`, shape `{src,line,at}`)
 * and accumulates events into a bounded ring buffer, auto-reconnecting with
 * exponential backoff on error/close. Use `enabled: false` to pause without
 * losing the buffer (e.g. a "pause" toggle in the Logs view — brief §4).
 *
 * Usage:
 *   const { items, connected } = useSSE<LogLine>('/api/logs/all', { maxBufferSize: 10000 });
 */
export function useSSE<T = unknown>(url: string, opts: UseSSEOptions<T> = {}): UseSSEResult<T> {
  const {
    parse = (e: MessageEvent) => JSON.parse(e.data) as T,
    maxBufferSize = DEFAULT_MAX_BUFFER,
    reconnectDelayMs = DEFAULT_RECONNECT_MS,
    maxReconnectDelayMs = DEFAULT_MAX_RECONNECT_MS,
    eventName,
    enabled = true,
  } = opts;

  const [items, setItems] = useState<T[]>([]);
  const [connected, setConnected] = useState(false);
  const [error, setError] = useState<unknown>(undefined);
  const bufferRef = useRef<T[]>([]);
  const parseRef = useRef(parse);
  parseRef.current = parse;

  useEffect(() => {
    if (!enabled) {
      setConnected(false);
      return;
    }

    let cancelled = false;
    let es: EventSource | undefined;
    let reconnectTimer: ReturnType<typeof setTimeout> | undefined;
    let attempt = 0;

    const connect = () => {
      if (cancelled) return;
      es = new EventSource(url);

      es.onopen = () => {
        if (cancelled) return;
        attempt = 0;
        setConnected(true);
        setError(undefined);
      };

      const onMessage = (event: MessageEvent) => {
        if (cancelled) return;
        try {
          const parsed = parseRef.current(event);
          const next = bufferRef.current;
          next.push(parsed);
          // Trim in batches rather than every push (O(n) shift is wasteful
          // per-message on a 10k ring) — brief §4 wants a bounded 10k list.
          if (next.length > maxBufferSize * 1.1) {
            bufferRef.current = next.slice(next.length - maxBufferSize);
          }
          setItems(bufferRef.current.slice());
        } catch (err) {
          setError(err);
        }
      };

      if (eventName) {
        es.addEventListener(eventName, onMessage as EventListener);
      } else {
        es.onmessage = onMessage;
      }

      es.onerror = (event) => {
        if (cancelled) return;
        setConnected(false);
        setError(event);
        es?.close();
        const delay = Math.min(
          reconnectDelayMs * 2 ** attempt,
          maxReconnectDelayMs
        );
        attempt += 1;
        reconnectTimer = setTimeout(connect, delay);
      };
    };

    connect();

    return () => {
      cancelled = true;
      if (reconnectTimer) clearTimeout(reconnectTimer);
      es?.close();
      setConnected(false);
    };
  }, [url, enabled, maxBufferSize, reconnectDelayMs, maxReconnectDelayMs, eventName]);

  const clear = () => {
    bufferRef.current = [];
    setItems([]);
  };

  return { items, connected, error, clear };
}
