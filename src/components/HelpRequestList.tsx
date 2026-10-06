"use client";

import { useRouter } from "next/navigation";
import { useState } from "react";
import { formatDate, SEV_CHIP } from "@/lib/format";
import { SEV_LABEL } from "@/lib/i18n";
import { HELP_STATUS_LABEL, type HelpRequestRow, type HelpStatus } from "@/lib/db/help-repo";

const CHIP: Record<HelpStatus, string> = { new: "chip-info", quoted: "chip-accent", in_progress: "chip-med", done: "chip-ok", cancelled: "chip-info" };

export function HelpRequestList({ rows }: { rows: HelpRequestRow[] }) {
  const router = useRouter();
  const [busy, setBusy] = useState<string | null>(null);
  async function cancel(id: string) {
    setBusy(id);
    await fetch(`/api/help-requests/${id}`, { method: "DELETE" }).catch(() => undefined);
    setBusy(null); router.refresh();
  }
  if (!rows.length) return <div className="mt-3 rounded-xl border border-dashed border-line-strong bg-surface px-6 py-8 text-center text-sm text-muted">Bạn chưa gửi yêu cầu nào.</div>;
  return (
    <ul className="mt-3 space-y-3">
      {rows.map((r) => (
        <li key={r.id} className="panel p-4">
          <div className="flex flex-wrap items-center gap-2"><span className={CHIP[r.status]}>{HELP_STATUS_LABEL[r.status]}</span><span className="mono truncate text-[14px] font-medium">{r.label}</span><span className="ml-auto text-xs text-faint">{formatDate(r.created_at)}</span></div>
          <ul className="mt-2 space-y-1 text-[14px]">{r.issues.slice(0, 5).map((i, k) => <li key={k} className="flex items-center gap-2"><span className={SEV_CHIP[i.severity]}>{SEV_LABEL[i.severity]}</span><span className="min-w-0 truncate">{i.title}</span></li>)}{r.issues.length > 5 && <li className="text-xs text-muted">… và {r.issues.length - 5} lỗi khác</li>}</ul>
          {r.quote && <div className="mt-3 rounded-xl border border-accent/20 bg-accent-soft/60 px-4 py-3"><p className="eyebrow !text-accent">phản hồi từ đội kỹ thuật</p><p className="mt-1 whitespace-pre-wrap text-[15px] leading-relaxed">{r.quote}</p></div>}
          {(r.status === "new" || r.status === "quoted") && <button type="button" onClick={() => cancel(r.id)} disabled={busy === r.id} className="mt-3 text-[13px] text-muted underline hover:text-crit">Huỷ yêu cầu</button>}
        </li>
      ))}
    </ul>
  );
}
