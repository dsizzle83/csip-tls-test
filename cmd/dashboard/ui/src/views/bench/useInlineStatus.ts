import { useEffect, useRef, useState } from 'react';

export interface InlineStatusState {
  text: string;
  ok: boolean;
}

/** Shows a ✓/✗ message for a few seconds after an inject/control call, then clears itself. */
export function useInlineStatus(clearAfterMs = 3000) {
  const [status, setStatus] = useState<InlineStatusState | null>(null);
  const timerRef = useRef<ReturnType<typeof setTimeout> | undefined>(undefined);

  useEffect(() => () => clearTimeout(timerRef.current), []);

  const show = (text: string, ok: boolean) => {
    setStatus({ text, ok });
    clearTimeout(timerRef.current);
    timerRef.current = setTimeout(() => setStatus(null), clearAfterMs);
  };

  return { status, show };
}
