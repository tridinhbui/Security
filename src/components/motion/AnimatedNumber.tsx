"use client";
import { useEffect, useRef, useState } from "react";
import { useReducedMotion } from "./useReducedMotion";

const easeOutExpo = (t: number) => (t === 1 ? 1 : 1 - Math.pow(2, -10 * t));

/** Số đếm chuyển mượt tới giá trị mới (rAF + easing). Có aria-label với giá trị cuối để trình đọc màn hình đọc đúng. */
export function AnimatedNumber({ value, duration = 900, className, delay = 0 }: { value: number; duration?: number; className?: string; delay?: number }) {
  const reduced = useReducedMotion();
  const [shown, setShown] = useState(reduced ? value : 0);
  const from = useRef(0);

  useEffect(() => {
    if (reduced) { setShown(value); from.current = value; return; }
    const start = from.current;
    let raf = 0, t0 = 0;
    const timer = setTimeout(() => {
      const tick = (t: number) => {
        t0 ||= t;
        const p = Math.min(1, (t - t0) / duration);
        const v = start + (value - start) * easeOutExpo(p);
        setShown(v);
        if (p < 1) raf = requestAnimationFrame(tick);
        else from.current = value;
      };
      raf = requestAnimationFrame(tick);
    }, delay);
    return () => { clearTimeout(timer); cancelAnimationFrame(raf); };
  }, [value, duration, delay, reduced]);

  return <span className={`num ${className ?? ""}`} aria-label={String(value)}>{Math.round(shown)}</span>;
}
