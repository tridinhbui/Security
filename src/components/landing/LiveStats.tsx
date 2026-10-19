"use client";

import { useEffect, useState } from "react";
import { AnimatedNumber } from "@/components/motion/AnimatedNumber";

interface Stats { scans: number; users: number }

/** Số lượt quét và số tài khoản (đọc từ cơ sở dữ liệu), tự làm mới mỗi 30 giây và khi quay lại tab. Ẩn hẳn nếu chưa lấy được số liệu. */
export function LiveStats({ initial }: { initial: Stats | null }) {
  const [s, setS] = useState(initial);
  useEffect(() => {
    let alive = true;
    const load = async () => {
      try {
        const r = await fetch("/api/stats", { cache: "no-store" });
        if (r.ok && alive) setS((await r.json()) as Stats);
      } catch { /* giữ số cũ */ }
    };
    const t = setInterval(() => { if (document.visibilityState === "visible") void load(); }, 30_000);
    const onVis = () => { if (document.visibilityState === "visible") void load(); };
    document.addEventListener("visibilitychange", onVis);
    return () => { alive = false; clearInterval(t); document.removeEventListener("visibilitychange", onVis); };
  }, []);
  if (!s) return null;
  return (
    <section aria-label="Số liệu trực tiếp" aria-live="polite" className="reveal mt-8 max-w-xl overflow-hidden rounded-2xl border border-accent/25 bg-gradient-to-br from-accent-soft via-white to-white shadow-card" style={{ ["--i" as string]: 5 }}>
      <div className="flex items-center gap-2 border-b border-accent/15 px-5 py-2.5">
        <span className="live-dot" aria-hidden />
        <span className="mono text-[11px] font-semibold uppercase tracking-[0.14em] text-accent">Trực tiếp</span>
        <span className="ml-auto text-xs text-muted">tự cập nhật mỗi 30 giây</span>
      </div>
      <dl className="grid grid-cols-2 divide-x divide-accent/15">
        <div className="px-5 py-4 sm:px-6 sm:py-5">
          <dd className="num text-4xl font-bold leading-none tracking-tight text-fg sm:text-5xl"><AnimatedNumber value={s.scans} /></dd>
          <dt className="mt-2 text-sm font-medium text-muted">lượt quét đã chạy</dt>
        </div>
        <div className="px-5 py-4 sm:px-6 sm:py-5">
          <dd className="num text-4xl font-bold leading-none tracking-tight text-accent sm:text-5xl"><AnimatedNumber value={s.users} /></dd>
          <dt className="mt-2 text-sm font-medium text-muted">người đã tạo tài khoản</dt>
        </div>
      </dl>
    </section>
  );
}
