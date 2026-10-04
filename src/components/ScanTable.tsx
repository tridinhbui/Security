import Link from "next/link";
import type { ScanRow } from "@/lib/db-types";
import { formatDate, gradeColor, relativeTime, scoreColor } from "@/lib/format";

export function ScanTable({ scans }: { scans: ScanRow[] }) {
  if (scans.length === 0) return <p className="text-sm text-muted mt-3">Chưa có lượt quét nào. Hãy dán một URL vào ô phía trên.</p>;
  return (
    <ul className="mt-3 divide-y divide-line border-y border-line">
      {scans.map((s) => (
        <li key={s.id}>
          <Link href={`/scans/${s.id}`} className="flex items-center gap-4 py-3.5 hover:bg-surface -mx-2 px-2 rounded">
            <span className={`num w-10 text-xl font-semibold ${scoreColor(s.score)}`}>{s.score ?? "—"}</span>
            <span className={`w-5 font-semibold ${gradeColor(s.grade)}`}>{s.grade ?? ""}</span>
            <span className="flex-1 min-w-0">
              <span className="block truncate">{s.normalized_url.replace(/^https?:\/\//, "")}</span>
              <span className="block text-xs text-muted num" title={formatDate(s.created_at)}>{relativeTime(s.created_at)}</span>
            </span>
            <span className={`text-xs ${s.status === "failed" ? "text-high" : s.status === "completed" ? "text-faint" : "text-muted"}`}>{s.status === "completed" ? "" : s.status === "failed" ? "Thất bại" : "Đang xử lý"}</span>
          </Link>
        </li>
      ))}
    </ul>
  );
}
