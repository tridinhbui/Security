"use client";
import { useEffect, useRef, useState } from "react";
import { useReducedMotion } from "./motion/useReducedMotion";

const STEPS: { t: string; v: string; log: string; tone?: "ok" }[] = [
  { t: "Phân giải bản ghi DNS", v: "1.2s", log: "Resolving example.com → 93.184.216.34", tone: "ok" },
  { t: "Kiểm tra cấu hình TLS", v: "2.1s", log: "TLSv1.3 · chứng chỉ còn 71 ngày", tone: "ok" },
  { t: "Phân tích HTTP header", v: "0.8s", log: "Status: 200 OK · Server: cloudflare" },
  { t: "Quét endpoint công khai", v: "1.4s", log: "robots.txt · sitemap.xml · security.txt" },
  { t: "Kiểm tra tài nguyên phía client", v: "1.9s", log: "6 script · 0 source map lộ" },
  { t: "Đánh giá dịch vụ bên thứ ba", v: "0.6s", log: "Không có trình theo dõi quảng cáo", tone: "ok" },
];
const TOTAL = 41;

function Node({ className, name, ms }: { className: string; name: string; ms: string }) {
  return (
    <div className={`absolute flex items-start gap-2 ${className}`}>
      <span className="relative mt-1 grid size-2.5 place-items-center"><span className="orbit-ping absolute inset-0 rounded-full bg-accent/60" /><span className="relative size-2.5 rounded-full bg-accent" /></span>
      <span className="leading-tight"><span className="mono block text-[11px] font-medium">{name}</span><span className="mono block text-[11px] text-faint">{ms}</span></span>
    </div>
  );
}

/**
 * Hình minh hoạ hero "đang sống": thẻ quét chạy lặp qua các giai đoạn (tiến độ, đếm, nhật ký), các nút mạng nhấp nháy, đường nối chạy dòng dữ liệu,
 * và các lớp có chiều sâu phản ứng với con trỏ/cuộn (xem HeroStage). Chỉ trang trí nên ẩn khỏi trình đọc màn hình.
 * Vòng lặp chỉ chạy khi hero đang nhìn thấy; người dùng giảm chuyển động nhận một khung tĩnh.
 */
export function HeroVisual() {
  const reduced = useReducedMotion();
  const root = useRef<HTMLDivElement>(null);
  const [k, setK] = useState(2); // số giai đoạn đã xong
  const [visible, setVisible] = useState(true);

  useEffect(() => {
    const el = root.current;
    if (!el) return;
    const io = new IntersectionObserver(([e]) => setVisible(!!e?.isIntersecting));
    io.observe(el);
    return () => io.disconnect();
  }, []);

  useEffect(() => {
    if (reduced || !visible) return;
    const t = setInterval(() => setK((v) => (v >= STEPS.length + 1 ? 0 : v + 1)), 1900);
    return () => clearInterval(t);
  }, [reduced, visible]);

  const done = Math.min(k, STEPS.length);
  const progress = k === 0 ? 0.04 : Math.min(1, (done + (k <= STEPS.length - 1 ? 0.55 : 0)) / STEPS.length);
  const count = Math.round(progress * TOTAL);
  const finished = done === STEPS.length;
  const log = STEPS.slice(0, Math.min(STEPS.length, done + 1)).slice(-3);

  return (
    <div ref={root} aria-hidden className="relative mx-auto hidden h-[520px] w-full max-w-[640px] select-none lg:block">
      <div className="depth-1 absolute right-[-40px] top-6 size-[480px]">
        <div className="bg-dots slow-spin absolute inset-0 rounded-full" />
        <div className="absolute inset-0 rounded-full bg-gradient-to-br from-white via-white to-accent/10 opacity-70" />
      </div>

      <svg viewBox="0 0 640 520" className="depth-1 absolute inset-0 size-full" fill="none">
        {["M200 70 C260 90 330 120 370 190", "M370 190 C430 120 500 70 560 60", "M370 190 C450 190 520 190 590 190", "M370 190 C450 260 520 330 580 360"].map((d) => (
          <g key={d}>
            <path d={d} stroke="var(--color-accent)" strokeOpacity=".22" />
            <path d={d} stroke="var(--color-accent)" strokeOpacity=".7" strokeWidth="1.5" strokeLinecap="round" className="data-flow" />
          </g>
        ))}
      </svg>

      <div className="depth-3 absolute left-0 top-0">
        <div className="float-y w-52 rounded-2xl border border-line bg-white/90 p-4 shadow-card backdrop-blur">
          <div className="flex items-start gap-2.5">
            <span className="mt-1.5 size-2 rounded-full bg-ok" />
            <div className="min-w-0"><p className="mono text-[13px] font-semibold">example.com</p><p className="mono mt-1 text-[11px] text-faint">93.184.216.34</p><p className="mono text-[11px] text-faint">US · Cloudflare</p></div>
          </div>
        </div>
      </div>

      <div className="depth-2 absolute left-[352px] top-[172px]">
        <span className="grid size-9 place-items-center rounded-full bg-accent/15"><span className="hub-pulse size-4 rounded-full border-[3px] border-white bg-accent shadow-glow" /></span>
      </div>
      <div className="depth-2 pointer-events-none absolute inset-0"><Node className="right-0 top-[44px]" name="US-EAST" ms="17ms" /></div>
      <div className="depth-2 pointer-events-none absolute inset-0"><Node className="right-[-8px] top-[176px]" name="EU-WEST" ms="72ms" /></div>
      <div className="depth-2 pointer-events-none absolute inset-0"><Node className="right-[8px] top-[340px]" name="ASIA" ms="98ms" /></div>

      <div className="depth-4 absolute left-[10px] top-[130px] w-[350px]">
        <div className="rounded-2xl border border-line bg-white p-5 shadow-card">
          <div className="flex items-baseline justify-between"><p className="text-[15px] font-semibold">{finished ? "Hoàn tất ✓" : "Đang quét…"}</p><p className="mono num text-[13px] text-muted">{count} / {TOTAL}</p></div>
          <div className="mt-3 h-1 overflow-hidden rounded-full bg-raised"><div className="h-full origin-left rounded-full bg-accent transition-transform duration-[1200ms] ease-out" style={{ transform: `scaleX(${progress})` }} /></div>
          <ul className="mt-4 space-y-2.5 text-[13px]">
            {STEPS.map((x, i) => {
              const s = i < done ? "done" : i === done && !finished ? "run" : "wait";
              return (
                <li key={x.t} className={`flex items-center gap-2.5 transition-colors duration-500 ${s === "wait" ? "text-faint" : "text-fg"}`}>
                  {s === "done" && <span className="pop grid size-4 place-items-center rounded-full bg-ok text-white"><svg viewBox="0 0 24 24" className="size-2.5" fill="none" stroke="currentColor" strokeWidth="4" strokeLinecap="round" strokeLinejoin="round"><path d="m5 12.5 4.5 4.5L19 7.5" /></svg></span>}
                  {s === "run" && <span className="spin-ring size-4 rounded-full border-[3px] border-accent/25 border-t-accent" />}
                  {s === "wait" && <span className="size-4 rounded-full border-2 border-line-strong" />}
                  <span className="flex-1">{x.t}</span><span className="mono text-[11px] text-faint">{s === "done" ? x.v : "···"}</span>
                </li>
              );
            })}
          </ul>
          <div className="mono mt-4 min-h-[88px] space-y-0.5 rounded-lg bg-surface px-3 py-2.5 text-[11px] leading-5">
            {log.map((x, i) => <p key={`${k}-${x.t}`} className={`log-in ${x.tone === "ok" ? "text-ok" : i === log.length - 1 ? "text-fg" : "text-muted"}`} style={{ animationDelay: `${i * 60}ms` }}>&gt; {x.log}</p>)}
            <p>&gt; <span className="cursor" /></p>
          </div>
        </div>
      </div>
    </div>
  );
}
