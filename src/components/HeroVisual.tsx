const STEPS: { t: string; s: "done" | "run" | "wait"; v?: string }[] = [
  { t: "Phân giải bản ghi DNS", s: "done", v: "1.2s" },
  { t: "Kiểm tra cấu hình TLS", s: "done", v: "2.1s" },
  { t: "Phân tích HTTP header", s: "run" },
  { t: "Quét endpoint công khai", s: "wait" },
  { t: "Kiểm tra tài nguyên phía client", s: "wait" },
  { t: "Đánh giá dịch vụ bên thứ ba", s: "wait" },
];

function Node({ className, name, ms }: { className: string; name: string; ms: string }) {
  return (
    <div className={`absolute flex items-start gap-2 ${className}`}>
      <span className="relative mt-1 grid size-2.5 place-items-center"><span className="orbit-ping absolute inset-0 rounded-full bg-accent/60" /><span className="relative size-2.5 rounded-full bg-accent" /></span>
      <span className="leading-tight"><span className="mono block text-[11px] font-medium">{name}</span><span className="mono block text-[11px] text-faint">{ms}</span></span>
    </div>
  );
}

/** Hình minh hoạ tĩnh cho hero: thẻ tiến trình quét + địa cầu chấm. Chỉ trang trí nên ẩn khỏi trình đọc màn hình. */
export function HeroVisual() {
  return (
    <div aria-hidden className="relative mx-auto hidden h-[520px] w-full max-w-[640px] select-none lg:block">
      <div className="bg-dots absolute right-[-40px] top-6 size-[480px] rounded-full" />
      <div className="absolute right-[-40px] top-6 size-[480px] rounded-full bg-gradient-to-br from-white via-white to-accent/10 opacity-70" />
      <svg viewBox="0 0 640 520" className="absolute inset-0 size-full" fill="none">
        <path d="M200 70 C260 90 330 120 370 190" stroke="var(--color-accent)" strokeOpacity=".35" />
        <path d="M370 190 C430 120 500 70 560 60" stroke="var(--color-accent)" strokeOpacity=".35" />
        <path d="M370 190 C450 190 520 190 590 190" stroke="var(--color-accent)" strokeOpacity=".35" />
        <path d="M370 190 C450 260 520 330 580 360" stroke="var(--color-accent)" strokeOpacity=".35" />
      </svg>

      <div className="float-y absolute left-0 top-0 w-52 rounded-2xl border border-line bg-white/90 p-4 shadow-card backdrop-blur">
        <div className="flex items-start gap-2.5">
          <span className="mt-1.5 size-2 rounded-full bg-ok" />
          <div className="min-w-0"><p className="mono text-[13px] font-semibold">example.com</p><p className="mono mt-1 text-[11px] text-faint">93.184.216.34</p><p className="mono text-[11px] text-faint">US · Cloudflare</p></div>
        </div>
      </div>

      <span className="absolute left-[352px] top-[172px] grid size-9 place-items-center rounded-full bg-accent/15"><span className="size-4 rounded-full border-[3px] border-white bg-accent shadow-glow" /></span>
      <Node className="right-0 top-[44px]" name="US-EAST" ms="17ms" />
      <Node className="right-[-8px] top-[176px]" name="EU-WEST" ms="72ms" />
      <Node className="right-[8px] top-[340px]" name="ASIA" ms="98ms" />

      <div className="absolute left-[10px] top-[130px] w-[350px] rounded-2xl border border-line bg-white p-5 shadow-card">
        <div className="flex items-baseline justify-between"><p className="text-[15px] font-semibold">Đang quét…</p><p className="mono num text-[13px] text-muted">24 / 41</p></div>
        <div className="mt-3 h-1 overflow-hidden rounded-full bg-raised"><div className="h-full w-[58%] rounded-full bg-accent" /></div>
        <ul className="mt-4 space-y-2.5 text-[13px]">
          {STEPS.map((x) => (
            <li key={x.t} className={`flex items-center gap-2.5 ${x.s === "wait" ? "text-faint" : "text-fg"}`}>
              {x.s === "done" && <span className="grid size-4 place-items-center rounded-full bg-ok text-white"><svg viewBox="0 0 24 24" className="size-2.5" fill="none" stroke="currentColor" strokeWidth="4" strokeLinecap="round" strokeLinejoin="round"><path d="m5 12.5 4.5 4.5L19 7.5" /></svg></span>}
              {x.s === "run" && <span className="size-4 rounded-full border-[3px] border-accent" />}
              {x.s === "wait" && <span className="size-4 rounded-full border-2 border-line-strong" />}
              <span className="flex-1">{x.t}</span><span className="mono text-[11px] text-faint">{x.v ?? "···"}</span>
            </li>
          ))}
        </ul>
        <div className="mono mt-4 space-y-0.5 rounded-lg bg-surface px-3 py-2.5 text-[11px] leading-5">
          <p>&gt; <b className="font-semibold">GET</b> https://example.com</p>
          <p className="text-ok">&gt; Status: 200 OK</p>
          <p className="text-muted">&gt; Server: cloudflare</p>
          <p className="text-muted">&gt; Content-Type: text/html; charset=utf-8</p>
          <p>&gt; <span className="cursor" /></p>
        </div>
      </div>
    </div>
  );
}
