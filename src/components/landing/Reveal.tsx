"use client";
import { useLayoutEffect, useRef } from "react";

/**
 * Hiện dần khi cuộn tới (IntersectionObserver, chỉ opacity + transform).
 * - Phần tử đã nằm trong màn hình lúc tải thì KHÔNG bị ẩn (không nhấp nháy); HTML từ server luôn hiển thị đầy đủ nếu JS không chạy.
 * - `from` chọn hướng trượt vào; `delay` (ms) tạo hiệu ứng lần lượt giữa các phần tử cùng nhóm.
 * - Tôn trọng prefers-reduced-motion: không ẩn, không chuyển động.
 */
export function Reveal({ children, className = "", delay = 0, from = "up" }: { children: React.ReactNode; className?: string; delay?: number; from?: "up" | "left" | "right" | "scale" }) {
  const ref = useRef<HTMLDivElement>(null);
  useLayoutEffect(() => {
    const el = ref.current;
    if (!el || window.matchMedia("(prefers-reduced-motion: reduce)").matches) return;
    if (el.getBoundingClientRect().top < window.innerHeight * 0.92) return;
    el.classList.add("rv-hide");
    const io = new IntersectionObserver(([e]) => {
      if (e?.isIntersecting) { el.classList.remove("rv-hide"); io.disconnect(); }
    }, { threshold: 0.12, rootMargin: "0px 0px -6% 0px" });
    io.observe(el);
    return () => io.disconnect();
  }, []);
  return <div ref={ref} data-from={from} className={`rv ${className}`} style={{ ["--d" as string]: `${delay}ms` }}>{children}</div>;
}
