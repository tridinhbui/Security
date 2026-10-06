"use client";

import { useEffect, useRef, useState } from "react";
import { MatMatSays } from "./matmat/MatMatSays";
import { Typed } from "./motion/Typed";

export type StageState = "done" | "run" | "wait";
export interface StageStep { label: string; state: StageState }
export interface StageLog { text: string; tone?: "muted" | "accent" | "ok" | "warn" }

/**
 * Màn hình quét chia đôi: trái là danh sách việc đang làm (x/N hoàn tất, chấm tiến độ, checklist, lời Mật Mật),
 * phải là “màn hình trực tiếp” của bộ quét (khung trình duyệt với địa chỉ đích, nhật ký chạy, đồng hồ, thanh thời gian).
 * Dùng chung cho quét thử miễn phí và quét trong tài khoản.
 */
export function ScanStage({ host, steps, logs, pct, say, footnote }: { host: string; steps: StageStep[]; logs: StageLog[]; pct: number; say?: string; footnote?: string }) {
  const done = steps.filter((s) => s.state === "done").length;
  const [secs, setSecs] = useState(0);
  const endRef = useRef<HTMLDivElement>(null);
  useEffect(() => { const t = setInterval(() => setSecs((v) => v + 1), 1000); return () => clearInterval(t); }, []);
  useEffect(() => { endRef.current?.scrollIntoView({ block: "end" }); }, [logs.length]);
  const mm = String(Math.floor(secs / 60)).padStart(2, "0"), ss = String(secs % 60).padStart(2, "0");
  const tone = { muted: "text-white/55", accent: "text-sky-300", ok: "text-emerald-400", warn: "text-amber-300" } as const;

  return (
    <div className="reveal grid gap-4 lg:h-[32rem] lg:grid-cols-[minmax(0,26rem)_minmax(0,1fr)]" role="status" aria-label="Đang quét website">
      {/* trái: việc đang làm */}
      <section className="panel flex min-h-0 flex-col overflow-hidden">
        <div className="border-b border-line p-4">
          <p className="text-sm"><b className="font-semibold">{done}/{steps.length}</b> <span className="text-muted">bước hoàn tất</span></p>
          <div className="mt-3 flex items-center" aria-hidden>
            {steps.map((s, i) => (
              <div key={i} className="flex flex-1 items-center last:flex-none">
                <span className={`grid size-3.5 shrink-0 place-items-center rounded-full border-2 transition-colors ${s.state === "done" ? "border-ok bg-ok" : s.state === "run" ? "border-accent bg-white" : "border-line-strong bg-white"}`}>{s.state === "run" && <span className="size-1.5 rounded-full bg-accent" />}</span>
                {i < steps.length - 1 && <span className={`h-0.5 flex-1 transition-colors ${s.state === "done" ? "bg-ok" : "bg-line"}`} />}
              </div>
            ))}
          </div>
        </div>
        {say && <div className="border-b border-line p-4"><MatMatSays text={say} cps={70} /></div>}
        <ol className="min-h-0 flex-1 space-y-0.5 overflow-y-auto p-3">
          {steps.map((s) => (
            <li key={s.label} className={`flex items-center gap-3 rounded-lg px-2.5 py-2 text-[14px] transition-colors ${s.state === "run" ? "bg-accent-soft/70 font-medium" : s.state === "wait" ? "text-faint" : "text-muted"}`}>
              {s.state === "done" ? <span className="pop grid size-4 shrink-0 place-items-center rounded-full bg-ok text-white"><svg viewBox="0 0 24 24" className="size-2.5" fill="none" stroke="currentColor" strokeWidth="4" strokeLinecap="round" strokeLinejoin="round"><path d="m5 12.5 4.5 4.5L19 7.5" /></svg></span>
                : s.state === "run" ? <span className="spin-ring size-4 shrink-0 rounded-full border-[3px] border-accent/25 border-t-accent" /> : <span className="size-4 shrink-0 rounded-full border-2 border-line-strong" />}
              <span className="min-w-0">{s.label}</span>
            </li>
          ))}
        </ol>
        {footnote && <p className="border-t border-line p-3 text-xs text-faint">{footnote}</p>}
      </section>

      {/* phải: màn hình trực tiếp */}
      <section className="panel flex min-h-[20rem] min-w-0 flex-col overflow-hidden" aria-hidden>
        <div className="flex items-center gap-3 border-b border-line bg-surface px-3.5 py-2.5">
          <span className="flex gap-1.5"><span className="term-dot" /><span className="term-dot" /><span className="term-dot" /></span>
          <span className="mono min-w-0 flex-1 truncate rounded-md border border-line bg-white px-3 py-1 text-center text-[12.5px] text-muted">https://{host}</span>
        </div>
        <div className="relative min-h-0 flex-1 overflow-hidden bg-[#0b1220]">
          <div className="pointer-events-none absolute inset-0 opacity-[0.07] [background-image:linear-gradient(#fff_1px,transparent_1px),linear-gradient(90deg,#fff_1px,transparent_1px)] [background-size:32px_32px]" />
          <div className="pointer-events-none absolute -right-16 -top-16 size-64 rounded-full bg-sky-500/10 blur-3xl" />
          <div className="relative h-full space-y-1 overflow-y-auto p-4 font-mono text-[12.5px] leading-6">
            {logs.map((l, i) => (
              <div key={i} className="flex gap-2.5">
                <span className="select-none text-white/30">{String(i + 1).padStart(2, "0")}</span>
                <span className={`min-w-0 break-words ${tone[l.tone ?? "muted"]}`}>{i === logs.length - 1 ? <Typed text={l.text} cps={70} /> : l.text}</span>
              </div>
            ))}
            <div ref={endRef} />
          </div>
        </div>
        <div className="flex items-center gap-3 border-t border-line bg-white px-3.5 py-2.5 text-xs text-muted">
          <span className="relative grid size-2.5 place-items-center"><span className="orbit-ping absolute inset-0 rounded-full bg-ok/60" /><span className="relative size-2 rounded-full bg-ok" /></span>
          <span className="font-medium text-fg">live</span>
          <div className="scanline h-1 min-w-0 flex-1 overflow-hidden rounded-full bg-line"><div className="h-full rounded-full bg-accent transition-[width] duration-700 ease-out" style={{ width: `${Math.max(pct, 4)}%` }} /></div>
          <span className="mono num">{mm}:{ss}</span>
        </div>
      </section>
    </div>
  );
}
