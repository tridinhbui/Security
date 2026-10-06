"use client";

import Link from "next/link";
import { useEffect, useState } from "react";
import { ScoreRing } from "./motion/ScoreRing";

type Status = "pass" | "warning" | "fail";
interface Item { id: string; label: string; status: Status; text: string }
interface Result { host: string; score: number; grade: string; counts: Record<Status, number>; items: Item[]; cached?: boolean }

const CHIP: Record<Status, { cls: string; label: string }> = { pass: { cls: "chip-ok", label: "Đạt" }, warning: { cls: "chip-med", label: "Cảnh báo" }, fail: { cls: "chip-crit", label: "Lỗi" } };

/**
 * Gọi /api/quick-scan (backend thật, không dữ liệu giả) rồi hiển thị: điểm 0–100, từng mục Đạt/Cảnh báo/Lỗi bằng tiếng Việt,
 * và lời mời quét đầy đủ. URL người dùng nhập được giữ nguyên trong liên kết đăng ký/đăng nhập để tự điền sau khi vào tài khoản.
 */
export function QuickScanRunner({ url, authed, ruleCount }: { url: string; authed: boolean; ruleCount: number }) {
  const [state, setState] = useState<{ kind: "loading" } | { kind: "ok"; r: Result } | { kind: "error"; message: string; limited: boolean }>({ kind: "loading" });

  useEffect(() => {
    setState({ kind: "loading" });
    const ctl = new AbortController();
    (async () => {
      try {
        const res = await fetch("/api/quick-scan", { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify({ url }), signal: ctl.signal });
        const body = await res.json().catch(() => ({}));
        if (!res.ok) return setState({ kind: "error", message: body.message ?? "Không thể quét lúc này. Vui lòng thử lại sau.", limited: res.status === 429 });
        setState({ kind: "ok", r: body as Result });
      } catch (e) {
        if ((e as Error).name !== "AbortError") setState({ kind: "error", message: "Lỗi mạng. Vui lòng thử lại.", limited: false });
      }
    })();
    return () => ctl.abort();
  }, [url]);

  const fullScanPath = `/quet-co-ban?scan=${encodeURIComponent(url)}`;
  const cta = authed ? fullScanPath : `/signup?next=${encodeURIComponent(fullScanPath)}`;

  return (
    <section className="mt-8" aria-live="polite" aria-busy={state.kind === "loading"}>
      {state.kind === "loading" && (
        <div className="panel flex items-center gap-4 p-6" role="status">
          <span className="spin-ring size-5 rounded-full border-[3px] border-accent/25 border-t-accent" aria-hidden />
          <div><p className="font-medium">Đang kiểm tra website…</p><p className="text-sm text-muted">Thường mất vài giây. Chúng tôi chỉ đọc những gì ai cũng thấy được.</p></div>
        </div>
      )}

      {state.kind === "error" && (
        <div className="panel p-6" role="alert">
          <p className="font-medium text-crit">Chưa quét được</p>
          <p className="mt-1 text-sm text-muted">{state.message}</p>
          {state.limited && <Link href={cta} className="btn-primary mt-4">Đăng ký để quét tiếp</Link>}
        </div>
      )}

      {state.kind === "ok" && (
        <>
          <div className="panel p-5 sm:p-6">
            <div className="grid items-center gap-5 sm:grid-cols-[auto_1fr]">
              <ScoreRing score={state.r.score} grade={state.r.grade} size={132} />
              <div>
                <p className="mono text-sm text-muted">{state.r.host}</p>
                <div className="mt-2 flex flex-wrap gap-2">
                  <span className="chip-ok">{state.r.counts.pass} Đạt</span>
                  <span className="chip-med">{state.r.counts.warning} Cảnh báo</span>
                  <span className="chip-crit">{state.r.counts.fail} Lỗi</span>
                </div>
                <p className="mt-3 text-xs text-faint">Quét nhanh chỉ xem trang chủ nên điểm tối đa là 90.{state.r.cached ? " Kết quả được lưu tạm trong vài giờ." : ""}</p>
              </div>
            </div>
            <ul className="mt-5 divide-y divide-line border-t border-line">
              {state.r.items.map((i, n) => (
                <li key={`${n}:${i.id}`} className="flex items-start gap-3 py-3">
                  <span className={`${CHIP[i.status].cls} mt-0.5 w-[5.5rem] shrink-0 justify-center whitespace-nowrap`}>{CHIP[i.status].label}</span>
                  <span className="min-w-0 text-sm"><span className="block font-medium">{i.label}</span><span className="block text-muted">{i.text}</span></span>
                </li>
              ))}
            </ul>
          </div>

          <div className="panel mt-6 flex flex-col gap-4 bg-surface p-5 sm:flex-row sm:items-center sm:justify-between sm:p-6">
            <div>
              <h2 className="text-lg font-semibold tracking-tight">Muốn kiểm tra kỹ hơn?</h2>
              <p className="mt-1 text-sm text-muted">{authed ? "Chạy" : "Đăng nhập để chạy"} {ruleCount}+ kiểm tra, xem hướng dẫn fix và lưu lịch sử.</p>
            </div>
            <div className="flex shrink-0 flex-col items-start gap-2 sm:items-end">
              <Link href={cta} className="btn-primary">Quét đầy đủ miễn phí<svg viewBox="0 0 24 24" className="size-4" fill="none" stroke="currentColor" strokeWidth="2.2" strokeLinecap="round" strokeLinejoin="round" aria-hidden><path d="M5 12h14M13 6l6 6-6 6" /></svg></Link>
              {!authed && <Link href={`/login?next=${encodeURIComponent(fullScanPath)}`} className="text-sm text-muted hover:text-fg">Đã có tài khoản? Đăng nhập</Link>}
            </div>
          </div>
        </>
      )}
    </section>
  );
}
