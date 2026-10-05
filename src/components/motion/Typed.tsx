"use client";
import { useEffect, useRef, useState } from "react";
import { useReducedMotion } from "./useReducedMotion";

export interface TermLine { text: string; prefix?: string; tone?: "default" | "ok" | "warn" | "crit" | "muted" | "accent"; }

const TONE: Record<NonNullable<TermLine["tone"]>, string> = { default: "text-fg", ok: "text-ok", warn: "text-med", crit: "text-crit", muted: "text-faint", accent: "text-accent" };

/**
 * Văn bản "được viết ra từng phần" như một engine bảo mật đang xuất kết quả.
 * - Nhanh (mặc định ~140 ký tự/giây, chia theo khung hình, không dùng setInterval cố định).
 * - Có thể ngắt: bấm "Bỏ qua" hoặc phím Esc để hiện ngay toàn bộ.
 * - Tôn trọng giảm chuyển động: hiện ngay.
 * - Trình đọc màn hình luôn nhận văn bản đầy đủ (aria-label), phần đang gõ ẩn khỏi cây truy cập.
 */
export function Typed({ text, play = true, cps = 140, onDone, cursor = true, className }: { text: string; play?: boolean; cps?: number; onDone?: () => void; cursor?: boolean; className?: string }) {
  const reduced = useReducedMotion();
  const instant = reduced || !play;
  const [n, setN] = useState(instant ? text.length : 0);
  const done = useRef(false);

  useEffect(() => {
    if (instant) { setN(text.length); if (!done.current) { done.current = true; onDone?.(); } return; }
    done.current = false;
    setN(0);
    let raf = 0, t0 = 0;
    const tick = (t: number) => {
      t0 ||= t;
      const k = Math.min(text.length, Math.floor(((t - t0) / 1000) * cps));
      setN(k);
      if (k < text.length) raf = requestAnimationFrame(tick);
      else if (!done.current) { done.current = true; onDone?.(); }
    };
    raf = requestAnimationFrame(tick);
    return () => cancelAnimationFrame(raf);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [text, instant, cps]);

  const typing = n < text.length;
  return (
    <span className={className} aria-label={text}>
      <span aria-hidden>{text.slice(0, n)}</span>
      {cursor && typing && <span className="cursor" aria-hidden />}
    </span>
  );
}

/**
 * Khối terminal gõ lần lượt từng dòng. `storageKey` giúp chỉ phát hiệu ứng MỘT lần cho mỗi báo cáo trong phiên
 * (mở lại báo cáo thì hiện ngay, không bắt người dùng xem lại hiệu ứng).
 */
export function TermTyper({ lines, title, storageKey, fresh }: { lines: TermLine[]; title: string; storageKey: string; fresh: boolean }) {
  const reduced = useReducedMotion();
  const [seen, setSeen] = useState(true); // mặc định coi như đã xem → render tĩnh ở server, tránh nhấp nháy
  const [idx, setIdx] = useState(0);
  const [skipped, setSkipped] = useState(false);

  useEffect(() => {
    let already = false;
    try { already = sessionStorage.getItem(storageKey) === "1"; } catch { /* không có storage */ }
    setSeen(already || !fresh);
  }, [storageKey, fresh]);

  const play = !seen && !reduced && !skipped;
  const finish = () => { setSkipped(true); try { sessionStorage.setItem(storageKey, "1"); } catch { /* bỏ qua */ } };
  useEffect(() => {
    if (!play) return;
    const onKey = (e: KeyboardEvent) => { if (e.key === "Escape") finish(); };
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [play]);

  const visible = play ? lines.slice(0, idx + 1) : lines;
  const allDone = !play || idx >= lines.length;
  return (
    <div className="term" onClick={play ? finish : undefined}>
      <div className="term-bar">
        <span className="term-dot" /><span className="term-dot" /><span className="term-dot" />
        <span className="ml-1 font-mono">{title}</span>
        {play && <button type="button" onClick={(e) => { e.stopPropagation(); finish(); }} className="ml-auto rounded px-1.5 py-0.5 text-[11px] text-muted hover:bg-raised hover:text-fg">Bỏ qua (Esc)</button>}
      </div>
      <div className="term-body space-y-0.5" aria-live={play ? "off" : undefined}>
        {visible.map((l, i) => {
          const current = play && i === idx;
          return (
            <div key={i} className="flex gap-2">
              <span className={`prompt shrink-0 ${l.tone && l.tone !== "default" ? TONE[l.tone] : ""}`} aria-hidden>{l.prefix ?? ">"}</span>
              <span className={`min-w-0 break-words ${TONE[l.tone ?? "default"]}`}>
                {current ? <Typed text={l.text} onDone={() => setIdx((v) => { const nx = v + 1; if (nx >= lines.length) { try { sessionStorage.setItem(storageKey, "1"); } catch { /* */ } } return nx; })} /> : l.text}
              </span>
            </div>
          );
        })}
        {allDone && <div className="flex gap-2"><span className="prompt" aria-hidden>$</span><span className="cursor" aria-hidden /></div>}
      </div>
    </div>
  );
}
