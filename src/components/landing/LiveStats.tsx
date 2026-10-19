"use client";

import { useEffect, useState } from "react";
import { AnimatedNumber } from "@/components/motion/AnimatedNumber";

/** Số lượt quét và số tài khoản THẬT, tự làm mới mỗi 30 giây (và khi quay lại tab). Ẩn hẳn nếu chưa lấy được số liệu. */
export function LiveStats({ initial }: { initial: { scans: number; users: number } | null }) {
  const [s, setS] = useState(initial);
  useEffect(() => {
    let alive = true;
    const load = async () => {
      try {
        const r = await fetch("/api/stats", { cache: "no-store" });
        if (r.ok && alive) setS((await r.json()) as { scans: number; users: number });
      } catch { /* giữ số cũ */ }
    };
    const t = setInterval(() => { if (document.visibilityState === "visible") void load(); }, 30_000);
    const onVis = () => { if (document.visibilityState === "visible") void load(); };
    document.addEventListener("visibilitychange", onVis);
    return () => { alive = false; clearInterval(t); document.removeEventListener("visibilitychange", onVis); };
  }, []);
  if (!s) return null;
  return (
    <>
      <li className="pill" aria-live="polite"><span className="live-dot !size-2" aria-hidden /><span><AnimatedNumber value={s.scans} /> lượt quét đã chạy</span></li>
      {/* Làm nổi bật số người dùng: viền và nền màu nhấn, chữ đậm, chấm nhịp để thu hút mắt (vẫn là số thật). */}
      <li className="pill !border-accent/50 !bg-accent-soft font-semibold text-accent shadow-[0_0_0_4px_rgba(11,87,255,0.08)]"><span className="live-dot !size-2" aria-hidden /><span><AnimatedNumber value={s.users} className="font-bold" /> người đã tạo tài khoản</span></li>
    </>
  );
}
