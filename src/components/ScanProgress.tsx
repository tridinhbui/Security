"use client";
import { useRouter } from "next/navigation";
import { useEffect, useMemo, useRef, useState } from "react";
import type { ScanStatus } from "@/lib/db-types";
import { ALL_STEPS, progressFraction, STAGE_GROUPS, stepStates, type StepState } from "@/lib/scan-stages";
import { MatMatSays } from "./matmat/MatMatSays";
import { Typed } from "./motion/Typed";

const SAYS: Record<string, string> = {
  queued: "Mình xếp hàng cho bạn rồi, sắp tới lượt nè. Bạn cứ ngồi nghỉ một chút nhé ☕",
  validating: "Mình đang kiểm tra xem địa chỉ này có đúng và quét được không…",
  scanning_transport: "Mình đang thử gõ cửa chính của website, xem ổ khoá HTTPS có chắc không 🔐",
  checking_headers: "Giờ mình đọc các “biển báo an toàn” mà website dán ở cửa…",
  analyzing_client: "Mình đang nhìn xem trang có để lộ thứ gì không nên lộ, như ghi chú hay khoá bí mật 🔍",
  generating_report: "Sắp xong rồi! Mình đang viết báo cáo bằng ngôn ngữ dễ hiểu cho bạn ✍️",
  completed: "Xong rồi nè! Mình mở báo cáo cho bạn đây 🎉",
};

const StepIcon = ({ s }: { s: StepState }) =>
  s === "done" ? (
    <span className="pop grid size-5 place-items-center rounded-full bg-ok text-white" aria-label="Hoàn tất"><svg viewBox="0 0 24 24" className="size-3" fill="none" stroke="currentColor" strokeWidth="3.2" strokeLinecap="round" strokeLinejoin="round"><path d="m5 12.5 4.5 4.5L19 7.5" /></svg></span>
  ) : s === "running" ? (
    <span className="grid size-5 place-items-center" aria-label="Đang quét"><span className="live-dot" /></span>
  ) : (
    <span className="grid size-5 place-items-center" aria-label="Đang chờ"><span className="size-2 rounded-full border border-line-strong bg-white" /></span>
  );

/** Màn hình quét: thanh tiến độ, danh sách chín bước và nhật ký terminal. Lưu cờ "vừa hoàn tất" để báo cáo phát hiệu ứng xuất kết quả. */
export function ScanProgress({ scanId, initialStatus, url }: { scanId: string; initialStatus: ScanStatus; url: string }) {
  const router = useRouter();
  const [status, setStatus] = useState<ScanStatus>(initialStatus);
  const [stale, setStale] = useState(false);
  const [elapsed, setElapsed] = useState(0);
  const [log, setLog] = useState<{ text: string; tone: "muted" | "accent" | "ok" }[]>([{ text: `vibesec scan ${url}`, tone: "accent" }]);
  const seen = useRef(new Set<string>([initialStatus]));

  useEffect(() => {
    const t = setInterval(() => setElapsed((v) => v + 1), 1000);
    return () => clearInterval(t);
  }, []);

  useEffect(() => {
    let stop = false, ticks = 0;
    const poll = async () => {
      if (stop) return;
      try {
        const res = await fetch(`/api/scans/${scanId}`, { cache: "no-store" });
        if (res.ok) {
          const s = (await res.json()) as { status: ScanStatus };
          setStatus(s.status);
          if (s.status === "completed") { try { sessionStorage.setItem(`vibesec-fresh-${scanId}`, "1"); } catch { /* bỏ qua */ } }
          if (s.status === "completed" || s.status === "failed") { setTimeout(() => router.refresh(), s.status === "completed" ? 650 : 0); return; }
        }
      } catch { /* lỗi tạm thời: tiếp tục hỏi lại */ }
      ticks++;
      if (ticks > 60) setStale(true);
      setTimeout(poll, ticks < 10 ? 1200 : 2500);
    };
    void poll();
    return () => { stop = true; };
  }, [scanId, router]);

  // Nhật ký: thêm một dòng khi giai đoạn thật của máy chủ thay đổi.
  useEffect(() => {
    const g = STAGE_GROUPS.find((x) => x.server === status);
    if (!g || seen.current.has(status)) return;
    seen.current.add(status);
    setLog((l) => [...l, ...g.steps.map((s) => ({ text: `${s.label}…`, tone: "muted" as const }))].slice(-14));
  }, [status]);
  useEffect(() => {
    if (status === "completed") setLog((l) => [...l, { text: "Hoàn tất. Đang mở báo cáo…", tone: "ok" as const }]);
  }, [status]);

  const states = useMemo(() => stepStates(status), [status]);
  const pct = Math.round(progressFraction(status) * 100);
  const mm = String(Math.floor(elapsed / 60)).padStart(2, "0"), ss = String(elapsed % 60).padStart(2, "0");

  return (
    <div className="container-x max-w-3xl py-12 sm:py-16" aria-live="polite">
      <div className="flex flex-wrap items-center gap-3">
        <span className={status === "queued" ? "chip-info" : "chip-accent"}><span className="live-dot" aria-hidden />{status === "queued" ? "Đang chờ" : "Đang quét"}</span>
        <span className="mono num text-xs text-faint" aria-label="Thời gian đã trôi qua">{mm}:{ss}</span>
      </div>
      <h1 className="mono mt-4 break-all text-2xl font-semibold tracking-tight sm:text-3xl">{url}</h1>

      <div className="mt-8" role="progressbar" aria-valuenow={pct} aria-valuemin={0} aria-valuemax={100} aria-label="Tiến độ quét">
        <div className="scanline h-1.5 overflow-hidden rounded-full bg-line">
          <div className="h-full origin-left rounded-full bg-accent transition-[width] duration-700 ease-out" style={{ width: `${Math.max(pct, 4)}%` }} />
        </div>
        <div className="mono mt-2 flex justify-between text-[11px] text-faint"><span>{pct}%</span><span>Thường mất 10–30 giây</span></div>
      </div>

      <MatMatSays className="mt-8" text={SAYS[status] ?? SAYS.queued!} cps={80} />

      <div className="mt-10 grid gap-8 md:grid-cols-[1.1fr_1fr]">
        <ol className="space-y-1">
          {ALL_STEPS.map((s, i) => {
            const st = states[s.id] ?? "pending";
            return (
              <li key={s.id} className={`reveal flex items-start gap-3 rounded-lg px-2.5 py-2 transition-colors ${st === "running" ? "bg-accent-soft/70" : ""}`} style={{ ["--i" as string]: i }}>
                <span className="mt-0.5"><StepIcon s={st} /></span>
                <span className="min-w-0">
                  <span className={`block text-[15px] ${st === "pending" ? "text-faint" : st === "running" ? "font-medium text-fg" : "text-muted"}`}>{s.label}</span>
                  {st === "running" && <span className="fade-in block text-xs text-muted">{s.detail}</span>}
                </span>
              </li>
            );
          })}
        </ol>

        <div className="term h-fit self-start" role="log" aria-label="Nhật ký quét">
          <div className="term-bar"><span className="term-dot" /><span className="term-dot" /><span className="term-dot" /><span className="ml-1">vibesec — nhật ký</span></div>
          <div className="term-body max-h-72 space-y-0.5 overflow-y-auto">
            {log.map((l, i) => (
              <div key={i} className="flex gap-2">
                <span className={`prompt shrink-0 ${l.tone === "ok" ? "!text-ok" : ""}`} aria-hidden>{i === 0 ? "$" : l.tone === "ok" ? "✓" : ">"}</span>
                <span className={`min-w-0 break-words ${l.tone === "accent" ? "text-fg" : l.tone === "ok" ? "text-ok" : "text-muted"}`}>
                  {i === log.length - 1 && status !== "completed" ? <Typed text={l.text} cps={90} /> : l.text}
                </span>
              </div>
            ))}
            {status !== "completed" && <div className="flex gap-2"><span className="prompt" aria-hidden>&gt;</span><span className="cursor" aria-hidden /></div>}
          </div>
        </div>
      </div>

      <p className="mt-10 text-sm text-muted">Bạn có thể rời khỏi trang này — báo cáo sẽ nằm trong lịch sử quét của bạn.</p>
      {stale && <p role="status" className="mt-3 rounded-lg border border-med/30 bg-med/5 px-3.5 py-2.5 text-sm text-med">Lần này lâu hơn bình thường. Hệ thống có thể đang bận, nhưng lượt quét vẫn sẽ hoàn tất.</p>}
    </div>
  );
}
