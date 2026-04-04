import { useState, useEffect, useRef } from 'react';

export function useCountUp(target, duration = 1200, delay = 0) {
  const normalizedTarget = typeof target === 'number' ? target : parseInt(target, 10) || 0;
  const [value, setValue] = useState(normalizedTarget === 0 ? 0 : 0);
  const rafRef = useRef(null);
  const timerRef = useRef(null);

  useEffect(() => {
    const t = normalizedTarget;
    
    // Skip animation for 0 targets
    if (t === 0) return;

    // Clear any pending animations
    if (rafRef.current) cancelAnimationFrame(rafRef.current);
    if (timerRef.current) clearTimeout(timerRef.current);

    timerRef.current = setTimeout(() => {
      const start = performance.now();
      const step = (now) => {
        const progress = Math.min((now - start) / duration, 1);
        const eased = 1 - Math.pow(1 - progress, 3); // ease-out cubic
        setValue(Math.floor(eased * t));
        if (progress < 1) {
          rafRef.current = requestAnimationFrame(step);
        } else {
          setValue(t); // Ensure final value is exact
        }
      };
      rafRef.current = requestAnimationFrame(step);
    }, delay);

    return () => {
      if (timerRef.current) clearTimeout(timerRef.current);
      if (rafRef.current) cancelAnimationFrame(rafRef.current);
    };
  }, [normalizedTarget, duration, delay]);

  return value;
}
