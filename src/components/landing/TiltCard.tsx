"use client";
import { useRef } from "react";

/** Thẻ nghiêng rất nhẹ (tối đa 3°) theo con trỏ, kèm vệt sáng đi theo. Chỉ trên thiết bị có chuột; không làm gì khi giảm chuyển động. */
export function TiltCard({ children, className = "" }: { children: React.ReactNode; className?: string }) {
  const ref = useRef<HTMLDivElement>(null);
  const raf = useRef(0);
  const enabled = () => typeof window !== "undefined" && window.matchMedia("(hover: hover) and (pointer: fine)").matches && !window.matchMedia("(prefers-reduced-motion: reduce)").matches;
  const move = (e: React.PointerEvent) => {
    if (!enabled()) return;
    const el = ref.current!, r = el.getBoundingClientRect();
    const x = (e.clientX - r.left) / r.width, y = (e.clientY - r.top) / r.height;
    cancelAnimationFrame(raf.current);
    raf.current = requestAnimationFrame(() => {
      el.style.setProperty("--rx", `${((0.5 - y) * 5).toFixed(2)}deg`);
      el.style.setProperty("--ry", `${((x - 0.5) * 6).toFixed(2)}deg`);
      el.style.setProperty("--gx", `${(x * 100).toFixed(1)}%`);
      el.style.setProperty("--gy", `${(y * 100).toFixed(1)}%`);
    });
  };
  const leave = () => {
    cancelAnimationFrame(raf.current);
    const el = ref.current!;
    el.style.setProperty("--rx", "0deg"); el.style.setProperty("--ry", "0deg");
  };
  return <div className="tilt-wrap"><div ref={ref} onPointerMove={move} onPointerLeave={leave} className={`tilt ${className}`}>{children}<span aria-hidden className="tilt-glare" /></div></div>;
}
