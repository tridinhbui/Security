"use client";
import { useMatMat } from "./matmat/MatMatProvider";

export interface CoverGroup { title: string; simple: string; tech: string[] }

/**
 * "Gồm những gì": ở chế độ Dễ hiểu chỉ hiện tên nhóm + một câu đời thường; chuyển sang Kỹ thuật mới hiện chi tiết từng kiểm tra.
 */
export function ScanCovers({ groups, columns = false }: { groups: CoverGroup[]; columns?: boolean }) {
  const { mode } = useMatMat();
  const technical = mode === "technical";
  return (
    <ul className={`mt-3 grid gap-x-8 gap-y-3 text-[15px] ${columns ? "sm:grid-cols-2" : ""}`}>
      {groups.map((g) => (
        <li key={g.title} className="flex gap-2.5">
          <span className="mt-1 text-ok" aria-hidden>✓</span>
          <span className="min-w-0">
            <span className="font-medium text-fg">{g.title}</span>
            {technical
              ? <span className="mono mt-1 block text-[12.5px] leading-5 text-muted">{g.tech.join(" · ")}</span>
              : <span className="block text-muted">{g.simple}</span>}
          </span>
        </li>
      ))}
    </ul>
  );
}
