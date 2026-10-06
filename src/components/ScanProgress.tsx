"use client";
import { useRouter } from "next/navigation";
import { useEffect, useMemo, useRef, useState } from "react";
import type { ScanStatus } from "@/lib/db-types";
import { ALL_STEPS, progressFraction, STAGE_GROUPS, stepStates, type StepState } from "@/lib/scan-stages";
import { ScanStage } from "./ScanStage";

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

const hostName = (u: string) => { try { return new URL(u).hostname; } catch { return u; } };
const ORDER: ScanStatus[] = STAGE_GROUPS.map((g) => g.server).concat("completed");
/** Dòng nhật ký chi tiết hiện dần trong mỗi giai đoạn (minh hoạ cho các việc bộ quét làm bên trong). */
const DETAIL: Partial<Record<ScanStatus, (h: string) => string[]>> = {
  queued: () => ["nhận yêu cầu quét", "cấp phiên cô lập, giới hạn 14 request / 2 MB / 12 giây"],
  validating: (h) => [`validate ${h}`, "chặn 10/8 · 172.16/12 · 192.168/16 · 169.254/16 ✓", `dig A ${h} · dig AAAA ${h}`, "xác minh IP công khai (chống DNS rebinding)"],
  scanning_transport: (h) => [`GET https://${h}/`, "bắt tay TLS: phiên bản, cipher, chuỗi chứng chỉ", "kiểm tra hạn chứng chỉ và HSTS", `GET http://${h}/ → theo dõi chuyển hướng`],
  checking_headers: () => ["đọc CSP, X-Frame-Options, nosniff, Referrer-Policy", "phân tích sâu CSP: unsafe-inline, nguồn quá rộng", "đọc Set-Cookie: Secure / HttpOnly / SameSite", "gửi Origin giả lập để kiểm tra CORS"],
  analyzing_client: (h) => [`GET https://${h}/robots.txt · sitemap.xml · security.txt`, "parse HTML: script, form, nội dung hỗn hợp", "tải script công khai, tìm khoá bí mật bị lộ", "đối chiếu thư viện với danh sách lỗ hổng (CVE)", "tìm source map, ghi chú, địa chỉ nội bộ"],
  generating_report: () => ["kiểm tra SPF / DMARC / CAA / DNSSEC", "chuỗi cung ứng script, chuỗi chuyển hướng, tính nhất quán header", "chấm điểm: trọng số mức độ × độ tin cậy", "soạn hướng dẫn khắc phục và lệnh kiểm tra lại"],
};
const PACE_MS = 3200; // mỗi giai đoạn hiển thị tối thiểu ngần ấy để người dùng theo dõi kịp
const LINE_MS = 800;

/** Màn hình quét chia đôi. Trạng thái HIỂN THỊ đi theo trạng thái thật của máy chủ nhưng không nhảy nhanh hơn PACE_MS mỗi giai đoạn. */
export function ScanProgress({ scanId, initialStatus, url }: { scanId: string; initialStatus: ScanStatus; url: string }) {
  const router = useRouter();
  const [status, setStatus] = useState<ScanStatus>(initialStatus); // trạng thái thật
  const [shown, setShown] = useState(0); // chỉ số trạng thái đang hiển thị trong ORDER
  const [stale, setStale] = useState(false);
  const [elapsed, setElapsed] = useState(0);
  const [log, setLog] = useState<{ text: string; tone: "muted" | "accent" | "ok" }[]>([{ text: `vibesec scan ${url}`, tone: "accent" }]);
  const realIdx = useRef(Math.max(0, ORDER.indexOf(initialStatus)));
  const failed = useRef(false);

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
          if (s.status === "failed") { failed.current = true; router.refresh(); return; }
          realIdx.current = Math.max(realIdx.current, ORDER.indexOf(s.status));
          if (s.status === "completed") { try { sessionStorage.setItem(`vibesec-fresh-${scanId}`, "1"); } catch { /* bỏ qua */ } return; }
        }
      } catch { /* lỗi tạm thời: tiếp tục hỏi lại */ }
      ticks++;
      if (ticks > 60) setStale(true);
      setTimeout(poll, ticks < 10 ? 1200 : 2500);
    };
    void poll();
    return () => { stop = true; };
  }, [scanId, router]);

  // Bước hiển thị tiến dần, không vượt quá trạng thái thật.
  useEffect(() => {
    const t = setInterval(() => setShown((v) => Math.min(v + 1, realIdx.current)), PACE_MS);
    return () => clearInterval(t);
  }, []);
  const view: ScanStatus = ORDER[Math.min(shown, ORDER.length - 1)]!;

  // Khi giai đoạn hiển thị cuối (completed) đã xong: mở báo cáo.
  useEffect(() => {
    if (view !== "completed" || failed.current) return;
    setLog((l) => [...l, { text: "Hoàn tất. Đang mở báo cáo…", tone: "ok" as const }]);
    const t = setTimeout(() => router.refresh(), 900);
    return () => clearTimeout(t);
  }, [view, router]);

  // Nhật ký: khi giai đoạn hiển thị đổi thì ghi tên bước, rồi nhỏ giọt các dòng chi tiết.
  useEffect(() => {
    const g = STAGE_GROUPS.find((x) => x.server === view);
    if (!g) return;
    setLog((l) => [...l, ...g.steps.map((x) => ({ text: `▶ ${x.label}`, tone: "accent" as const }))].slice(-40));
    const lines = DETAIL[view]?.(hostName(url)) ?? [];
    let i = 0;
    const t = setInterval(() => {
      if (i >= lines.length) return clearInterval(t);
      const text = lines[i++]!;
      setLog((l) => [...l, { text, tone: "muted" as const }].slice(-40));
    }, LINE_MS);
    return () => clearInterval(t);
  }, [view, url]);

  const states = useMemo(() => stepStates(view), [view]);
  const pct = Math.round(progressFraction(view) * 100);
  const mm = String(Math.floor(elapsed / 60)).padStart(2, "0"), ss = String(elapsed % 60).padStart(2, "0");

  const host = hostName(url);
  const steps = ALL_STEPS.map((x) => ({ label: x.label, state: (states[x.id] === "done" ? "done" : states[x.id] === "running" ? "run" : "wait") as "done" | "run" | "wait" }));

  return (
    <div className="container-x max-w-6xl py-8 sm:py-12" aria-live="polite">
      <div className="mb-5 flex flex-wrap items-center gap-3">
        <span className={view === "queued" ? "chip-info" : "chip-accent"}><span className="live-dot" aria-hidden />{view === "queued" ? "Đang chờ" : "Đang quét"}</span>
        <h1 className="mono min-w-0 flex-1 truncate text-xl font-semibold tracking-tight sm:text-2xl">{url}</h1>
        <span className="mono num text-xs text-faint" aria-label="Thời gian đã trôi qua">{mm}:{ss}</span>
      </div>

      <ScanStage host={host} steps={steps} logs={log.map((l) => ({ text: l.text, tone: l.tone }))} pct={pct} say={SAYS[view] ?? SAYS.queued!} />

      <p className="mt-10 text-sm text-muted">Bạn có thể rời khỏi trang này — báo cáo sẽ nằm trong lịch sử quét của bạn.</p>
      {stale && <p role="status" className="mt-3 rounded-lg border border-med/30 bg-med/5 px-3.5 py-2.5 text-sm text-med">Lần này lâu hơn bình thường. Hệ thống có thể đang bận, nhưng lượt quét vẫn sẽ hoàn tất.</p>}
    </div>
  );
}
