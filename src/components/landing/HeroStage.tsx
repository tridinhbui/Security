"use client";
import { useEffect, useRef } from "react";

/**
 * Vùng hero có chiều sâu: ghi vị trí con trỏ (--px, --py ∈ [-1,1], có làm mượt) và tiến độ cuộn (--sy ∈ [0,1]) thành biến CSS.
 * Các lớp con dùng `.depth-*` để dịch chuyển theo biến này (chỉ transform → chạy trên GPU, không gây reflow).
 * Chỉ bật theo con trỏ trên thiết bị có chuột; tạm dừng khi hero ra khỏi màn hình; tắt hẳn khi người dùng chọn giảm chuyển động.
 */
export function HeroStage({ children, className = "" }: { children: React.ReactNode; className?: string }) {
  const ref = useRef<HTMLElement>(null);
  useEffect(() => {
    const el = ref.current;
    if (!el || window.matchMedia("(prefers-reduced-motion: reduce)").matches) return;
    const fine = window.matchMedia("(hover: hover) and (pointer: fine)").matches;
    let raf = 0, tx = 0, ty = 0, cx = 0, cy = 0, visible = true;

    const set = (n: string, v: number) => el.style.setProperty(n, v.toFixed(3));
    const frame = () => {
      raf = 0;
      cx += (tx - cx) * 0.09; cy += (ty - cy) * 0.09;
      set("--px", cx); set("--py", cy);
      if (Math.abs(tx - cx) > 0.002 || Math.abs(ty - cy) > 0.002) raf = requestAnimationFrame(frame);
    };
    const kick = () => { if (!raf && visible) raf = requestAnimationFrame(frame); };
    const onMove = (e: PointerEvent) => {
      const r = el.getBoundingClientRect();
      tx = ((e.clientX - r.left) / r.width - 0.5) * 2;
      ty = ((e.clientY - r.top) / r.height - 0.5) * 2;
      kick();
    };
    const onLeave = () => { tx = 0; ty = 0; kick(); };
    let ticking = false;
    const onScroll = () => {
      if (ticking || !visible) return;
      ticking = true;
      requestAnimationFrame(() => {
        ticking = false;
        const r = el.getBoundingClientRect();
        set("--sy", Math.min(1, Math.max(0, -r.top / r.height)));
      });
    };
    const io = new IntersectionObserver(([e]) => {
      visible = !!e?.isIntersecting;
      el.classList.toggle("is-paused", !visible); // tạm dừng animation CSS khi không nhìn thấy
    });
    io.observe(el);
    if (fine) { el.addEventListener("pointermove", onMove, { passive: true }); el.addEventListener("pointerleave", onLeave); }
    window.addEventListener("scroll", onScroll, { passive: true });
    return () => { io.disconnect(); cancelAnimationFrame(raf); el.removeEventListener("pointermove", onMove); el.removeEventListener("pointerleave", onLeave); window.removeEventListener("scroll", onScroll); };
  }, []);
  return <section ref={ref} className={`hero-stage ${className}`}>{children}</section>;
}
