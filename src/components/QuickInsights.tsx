"use client";

import { URGENCY, type AItem } from "./QuickAnalyst";
import { headline } from "./QuickAnalyst";

/** Các khối bổ sung cho trang kết quả quét nhanh: việc làm trước, điểm đến từ đâu, phạm vi quét, bộ lọc. */

export type StatusFilter = "issues" | "all" | "pass";
export const filterMatch = (f: StatusFilter, i: AItem) => (f === "all" ? true : f === "pass" ? i.status === "pass" : i.status !== "pass");

const URG_RANK = { now: 0, week: 1, later: 2 } as const;
const SEV_RANK: Record<string, number> = { critical: 0, high: 1, medium: 2, low: 3, info: 4 };

/** Ba việc nên làm trước: xếp theo mức khẩn cấp rồi theo độ nghiêm trọng. Bấm để mở mục đó. */
export function TopActions({ items, onPick }: { items: AItem[]; onPick: (n: number) => void }) {
  const ranked = items
    .map((i, n) => ({ i, n }))
    .filter(({ i }) => i.status !== "pass" && i.tech?.impact)
    .sort((a, b) => URG_RANK[a.i.tech!.impact!.urgency] - URG_RANK[b.i.tech!.impact!.urgency] || (SEV_RANK[a.i.tech!.severity] ?? 9) - (SEV_RANK[b.i.tech!.severity] ?? 9))
    .slice(0, 3);
  if (ranked.length === 0) return null;
  return (
    <div className="mt-4 rounded-xl border border-line bg-white p-3.5">
      <p className="eyebrow">nên làm trước</p>
      <ol className="mt-2 space-y-1.5">
        {ranked.map(({ i, n }, k) => (
          <li key={n}>
            <button type="button" onClick={() => onPick(n)} className="flex w-full items-start gap-2.5 rounded-lg px-1.5 py-1 text-left transition-colors hover:bg-surface">
              <span className="mono mt-0.5 grid size-5 shrink-0 place-items-center rounded-full bg-accent-soft text-[11px] font-semibold text-accent">{k + 1}</span>
              <span className="min-w-0 flex-1 text-sm leading-snug">{headline(i).title}</span>
              <span className={`${URGENCY[i.tech!.impact!.urgency].cls} hidden shrink-0 !normal-case sm:inline-flex`}>{URGENCY[i.tech!.impact!.urgency].label}</span>
            </button>
          </li>
        ))}
      </ol>
    </div>
  );
}

/** Minh bạch điểm số: điểm tối đa, từng khoản bị trừ (lớn nhất trước), và điểm cuối. */
export function ScoreBreakdown({ items, score, ceiling }: { items: AItem[]; score: number; ceiling: number }) {
  const deductions = items.filter((i) => i.status !== "pass" && (i.tech?.penalty ?? 0) > 0).sort((a, b) => b.tech!.penalty! - a.tech!.penalty!);
  const total = Math.round(deductions.reduce((s, i) => s + i.tech!.penalty!, 0) * 10) / 10;
  const raw = Math.max(0, Math.round(100 - total));
  const capped = score < Math.min(raw, ceiling);
  const max = Math.max(1, ...deductions.map((i) => i.tech!.penalty!));
  return (
    <section className="rounded-xl border border-line p-4">
      <h4 className="eyebrow">điểm đến từ đâu</h4>
      <dl className="mt-3 grid grid-cols-[1fr_auto] gap-x-4 gap-y-1.5 text-sm">
        <dt className="text-muted">Điểm khởi đầu</dt><dd className="mono num text-right">100</dd>
        <dt className="text-muted">Trừ do {deductions.length} phát hiện</dt><dd className="mono num text-right text-crit">−{total}</dd>
        {raw > ceiling && <><dt className="text-muted">Trần của quét nhanh (chỉ xem trang chủ)</dt><dd className="mono num text-right">{ceiling}</dd></>}
        {capped && <><dt className="text-muted">Trần theo mức nghiêm trọng (có phát hiện mức Cao hoặc Nghiêm trọng)</dt><dd className="mono num text-right">{score}</dd></>}
        <dt className="font-medium">Điểm cuối</dt><dd className="mono num text-right font-semibold">{score}</dd>
      </dl>
      {deductions.length > 0 && (
        <ul className="mt-4 space-y-2" aria-label="Các khoản bị trừ điểm">
          {deductions.slice(0, 8).map((i) => (
            <li key={i.id} className="grid grid-cols-[1fr_3.2rem] items-center gap-x-3 text-[13px]">
              <span className="min-w-0"><span className="block truncate">{headline(i).title}</span><span className="mt-1 block h-1 rounded-full bg-raised"><span className="block h-full rounded-full bg-crit/70" style={{ width: `${Math.max(6, (i.tech!.penalty! / max) * 100)}%` }} /></span></span>
              <span className="mono num text-right text-muted">−{i.tech!.penalty}</span>
            </li>
          ))}
        </ul>
      )}
      <p className="mt-3 text-xs leading-relaxed text-faint">Mỗi phát hiện bị trừ: trọng số mức độ (Nghiêm trọng 30, Cao 15, Trung bình 7, Thấp 3) × hệ số tin cậy (cao 1, vừa 0,7, thấp 0,4).</p>
    </section>
  );
}

const CHECKED = ["HTTPS/SSL và chuyển hướng", "Header bảo mật và CSP", "Cookie đặt khi truy cập ẩn danh", "CORS", "SPF / DMARC / CAA", "Thông tin lộ trên trang chủ", "security.txt", "Mixed content và script bên ngoài (SRI)"];
const NOT_CHECKED = ["Nội dung các file JavaScript: khoá bí mật, source map, thư viện lỗi thời", "Trang đăng nhập và rò rỉ phiên qua bộ nhớ đệm", "Chứng chỉ TLS chi tiết và phiên bản TLS cũ (trừ khi đã có trong bộ nhớ đệm)", "Phương thức HTTP được công bố", "Bản đồ endpoint và bề mặt GraphQL"];

/** Ranh giới của lượt quét: đã kiểm tra gì và chưa kiểm tra gì. */
export function CoverageStrip({ cta }: { cta: string }) {
  return (
    <section className="rounded-xl border border-line p-4">
      <h4 className="eyebrow">phạm vi quét nhanh</h4>
      <div className="mt-3 grid gap-4 sm:grid-cols-2">
        <div>
          <p className="text-xs font-medium text-ok">Đã kiểm tra</p>
          <ul className="mt-1.5 space-y-1 text-sm">{CHECKED.map((t) => <li key={t} className="flex gap-2"><span className="text-ok" aria-hidden>✓</span>{t}</li>)}</ul>
        </div>
        <div>
          <p className="text-xs font-medium text-muted">Chỉ có ở quét đầy đủ</p>
          <ul className="mt-1.5 space-y-1 text-sm text-muted">{NOT_CHECKED.map((t) => <li key={t} className="flex gap-2"><span aria-hidden>○</span>{t}</li>)}</ul>
        </div>
      </div>
      <p className="mt-3 text-xs text-faint">Quét nhanh là thụ động và chỉ xem trang chủ, nên không thấy được những mục bên phải. <a href={cta} className="font-medium text-accent hover:underline">Quét đầy đủ miễn phí →</a></p>
    </section>
  );
}

/** Bộ lọc trạng thái cho danh sách (mặc định chỉ hiện mục cần xử lý). */
export function StatusFilterBar({ value, onChange, counts }: { value: StatusFilter; onChange: (v: StatusFilter) => void; counts: Record<StatusFilter, number> }) {
  const opts: [StatusFilter, string][] = [["issues", "Cần xử lý"], ["pass", "Đạt"], ["all", "Tất cả"]];
  return (
    <div role="group" aria-label="Lọc theo trạng thái" className="flex gap-1.5 border-b border-line bg-white px-3 py-2">
      {opts.map(([k, label]) => (
        <button key={k} type="button" aria-pressed={value === k} onClick={() => onChange(k)}
          className={`rounded-md border px-2.5 py-1 text-xs font-medium transition-colors ${value === k ? "border-fg bg-fg text-white" : "border-line-strong bg-white text-muted hover:border-fg/40 hover:text-fg"}`}>{label} <span className="num opacity-70">{counts[k]}</span></button>
      ))}
    </div>
  );
}
