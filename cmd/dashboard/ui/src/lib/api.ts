// Thin typed fetch helpers for the /api/* surface proxied by cmd/dashboard
// (see CONTRACTS.md §6). All backend routes stay untouched by V2 — these
// helpers just add types, JSON handling, and a timeout knob for the health
// dots in the shell.

export class ApiError extends Error {
  status: number;
  body: unknown;

  constructor(message: string, status: number, body: unknown) {
    super(message);
    this.name = 'ApiError';
    this.status = status;
    this.body = body;
  }
}

export interface RequestOpts {
  /** Abort the request after this many ms. */
  timeoutMs?: number;
  signal?: AbortSignal;
  headers?: Record<string, string>;
}

async function request<T>(
  method: 'GET' | 'POST' | 'HEAD',
  path: string,
  body?: unknown,
  opts: RequestOpts = {}
): Promise<T> {
  const controller = new AbortController();
  const signals: AbortSignal[] = [controller.signal];
  if (opts.signal) signals.push(opts.signal);

  let timer: ReturnType<typeof setTimeout> | undefined;
  if (opts.timeoutMs) {
    timer = setTimeout(() => controller.abort(), opts.timeoutMs);
  }
  // Combine external abort (if any) with our own timeout controller.
  const externalSignal = opts.signal;
  if (externalSignal) {
    if (externalSignal.aborted) controller.abort();
    else externalSignal.addEventListener('abort', () => controller.abort(), { once: true });
  }

  try {
    const res = await fetch(path, {
      method,
      headers: {
        ...(body !== undefined ? { 'Content-Type': 'application/json' } : {}),
        ...opts.headers,
      },
      body: body !== undefined ? JSON.stringify(body) : undefined,
      signal: controller.signal,
    });

    if (method === 'HEAD') {
      if (!res.ok) throw new ApiError(`${method} ${path} -> ${res.status}`, res.status, null);
      return undefined as T;
    }

    const text = await res.text();
    const data = text ? safeJsonParse(text) : undefined;

    if (!res.ok) {
      throw new ApiError(`${method} ${path} -> ${res.status}`, res.status, data);
    }
    return data as T;
  } finally {
    if (timer) clearTimeout(timer);
  }
}

function safeJsonParse(text: string): unknown {
  try {
    return JSON.parse(text);
  } catch {
    return text;
  }
}

/** GET path and parse the JSON response body as T. */
export function getJSON<T>(path: string, opts?: RequestOpts): Promise<T> {
  return request<T>('GET', path, undefined, opts);
}

/** POST body (JSON-encoded) to path and parse the JSON response body as T. */
export function postJSON<T>(path: string, body?: unknown, opts?: RequestOpts): Promise<T> {
  return request<T>('POST', path, body, opts);
}

/** HEAD path; resolves on 2xx, rejects otherwise. Used for cheap health probes. */
export function head(path: string, opts?: RequestOpts): Promise<void> {
  return request<void>('HEAD', path, undefined, opts);
}

/**
 * Probe a health endpoint for the bench-health dot row: resolves true on 2xx,
 * false on anything else (network error, non-2xx, timeout) — never throws.
 * Falls back from HEAD to GET since not every backend implements HEAD.
 */
export async function probeHealth(path: string, timeoutMs = 2500): Promise<boolean> {
  try {
    await head(path, { timeoutMs });
    return true;
  } catch {
    // HEAD may be unsupported by the backend (405) or the request may have
    // failed outright — retry with GET before declaring the target down.
    try {
      await getJSON(path, { timeoutMs });
      return true;
    } catch {
      return false;
    }
  }
}
