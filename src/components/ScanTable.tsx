import Link from "next/link";
import type { ScanRow } from "@/lib/db-types";
import { formatDate, gradeColor, relativeTime, scoreColor } from "@/lib/format";

function Status({ s }: { s: ScanRow["status"] }) {
  if (s === "completed") return null;
  if (s === "failed") return <span className="chip-crit">Thất bại</span>;
  return <span className="chip-accent"><span className="live-dot" aria-hidden />{s === "queued" ? "Đang chờ" : "Đang quét"}</span>;
}

export function ScanTable({ scans }: { scans: ScanRow[] }) {
  if (scans.length === 0) {
    return (
      <div className="mt-4 rounded-xl border border-dashed border-line-strong bg-surface px-6 py-12 text-center">
        <p className="mono text-sm text-muted"><span className="prompt">$</span> chưa có lượt quét nào<span className="cursor" aria-hidden /></p>
        <p className="mt-2 text-sm text-muted">Hãy dán một URL vào ô phía trên để bắt đầu lượt quét đầu tiên.</p>
      </div>
    );
  }
  return (
    <ul className="mt-4 divide-y divide-line overflow-hidden rounded-xl border border-line bg-white shadow-crisp">
      {scans.map((s, i) => (
        <li key={s.id} className="reveal" style={{ ["--i" as string]: Math.min(i, 10) }}>
          <Link href={`/scans/${s.id}`} className="group flex items-center gap-4 px-4 py-3.5 transition-colors hover:bg-surface">
            <span className="grid w-14 shrink-0 place-items-center rounded-lg border border-line bg-surface py-1.5">
              <span className={`num text-lg font-semibold leading-none ${scoreColor(s.score)}`}>{s.score ?? "—"}</span>
              <span className={`mono mt-0.5 text-[10px] font-semibold ${gradeColor(s.grade)}`}>{s.grade ? `HẠNG ${s.grade}` : ""}</span>
            </span>
            <span className="min-w-0 flex-1">
              <span className="mono block truncate text-[14px] font-medium">{s.normalized_url.replace(/^https?:\/\//, "")}</span>
              <span className="num mt-0.5 flex items-center gap-2 text-xs text-muted" title={formatDate(s.created_at)}>{relativeTime(s.created_at)}<span className="chip-info !py-0">{s.mode === "quick" ? "cơ bản" : "nâng cao"}</span></span>
            </span>
            <Status s={s.status} />
            <svg viewBox="0 0 24 24" className="size-4 shrink-0 text-faint transition-transform duration-200 group-hover:translate-x-0.5" fill="none" stroke="currentColor" strokeWidth="2.2" strokeLinecap="round" strokeLinejoin="round" aria-hidden><path d="m9 6 6 6-6 6" /></svg>
          </Link>
        </li>
      ))}
    </ul>
  );
}
