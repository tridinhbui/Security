import Link from "next/link";
import type { ProjectScanRow } from "@/lib/db/project-repo";
import { formatDate, gradeColor, relativeTime, scoreColor } from "@/lib/format";
import { VERDICT_LABEL } from "@/lib/project/types";

const VERDICT_CHIP = { ready: "chip-ok", fix_first: "chip-med", not_ready: "chip-crit" } as const;

/** Danh sách gần đây dùng chung cho cả ba trang quét dự án. */
export function ProjectScanList({ scans, base, empty }: { scans: ProjectScanRow[]; base: string; empty: string }) {
  if (!scans.length) return <div className="mt-4 rounded-xl border border-dashed border-line-strong bg-surface px-6 py-10 text-center text-sm text-muted">{empty}</div>;
  return (
    <ul className="mt-4 divide-y divide-line overflow-hidden rounded-xl border border-line bg-white shadow-crisp">
      {scans.map((s) => (
        <li key={s.id}>
          <Link href={`${base}/${s.id}`} className="group flex items-center gap-4 px-4 py-3.5 transition-colors hover:bg-surface">
            <span className="grid w-14 shrink-0 place-items-center rounded-lg border border-line bg-surface py-1.5">
              <span className={`num text-lg font-semibold leading-none ${scoreColor(s.score)}`}>{s.score ?? "—"}</span>
              <span className={`mono mt-0.5 text-[10px] font-semibold ${gradeColor(s.grade)}`}>{s.grade ? `HẠNG ${s.grade}` : ""}</span>
            </span>
            <span className="min-w-0 flex-1">
              <span className="mono block truncate text-[14px] font-medium">{s.label}</span>
              <span className="num mt-0.5 block text-xs text-muted" title={formatDate(s.created_at)}>{relativeTime(s.created_at)}</span>
            </span>
            {s.verdict && <span className={`${VERDICT_CHIP[s.verdict]} hidden sm:inline-flex`}>{VERDICT_LABEL[s.verdict]}</span>}
            <svg viewBox="0 0 24 24" className="size-4 shrink-0 text-faint transition-transform duration-200 group-hover:translate-x-0.5" fill="none" stroke="currentColor" strokeWidth="2.2" strokeLinecap="round" strokeLinejoin="round" aria-hidden><path d="m9 6 6 6-6 6" /></svg>
          </Link>
        </li>
      ))}
    </ul>
  );
}
