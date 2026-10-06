"use client";

import { useRouter } from "next/navigation";
import { useState } from "react";
import { formatDate, SEV_CHIP } from "@/lib/format";
import { SEV_LABEL } from "@/lib/i18n";
import { HELP_STATUS_LABEL, type HelpRequestRow, type HelpStatus } from "@/lib/db/help-repo";

const SET: HelpStatus[] = ["new", "quoted", "in_progress", "done"];

export function AdminHelpRow({ r }: { r: HelpRequestRow }) {
  const router = useRouter();
  const [status, setStatus] = useState<HelpStatus>(r.status === "cancelled" ? "new" : r.status);
  const [quote, setQuote] = useState(r.quote);
  const [busy, setBusy] = useState(false);
  const [msg, setMsg] = useState("");
  const cancelled = r.status === "cancelled";
  async function save() {
    setBusy(true); setMsg("");
    const res = await fetch(`/api/admin/help-requests/${r.id}`, { method: "PATCH", headers: { "content-type": "application/json" }, body: JSON.stringify({ status, quote }) });
    setBusy(false); setMsg(res.ok ? "Đã lưu" : "Không lưu được"); if (res.ok) router.refresh();
  }
  return (
    <li className="panel p-4">
      <div className="flex flex-wrap items-center gap-x-3 gap-y-1"><span className={cancelled ? "chip-info" : "chip-accent"}>{HELP_STATUS_LABEL[r.status]}</span><span className="mono font-medium">{r.label}</span><span className="text-xs text-muted">{r.source_kind} · {r.email} · {r.contact}</span><span className="ml-auto text-xs text-faint">{formatDate(r.created_at)}</span></div>
      <ul className="mt-2 space-y-1.5 text-[14px]">{r.issues.map((i, k) => <li key={k}><span className={`${SEV_CHIP[i.severity]} mr-2`}>{SEV_LABEL[i.severity]}</span>{i.title}{i.evidence[0] && <span className="mono block pl-1 text-xs text-faint">{i.evidence[0]}</span>}</li>)}</ul>
      {r.note && <p className="mt-2 whitespace-pre-wrap rounded-lg bg-surface px-3 py-2 text-sm">{r.note}</p>}
      {!cancelled && (
        <div className="mt-3 grid gap-2 sm:grid-cols-[1fr_auto]">
          <textarea aria-label="Báo giá / phản hồi" value={quote} onChange={(e) => setQuote(e.target.value)} rows={2} maxLength={2000} placeholder="Báo giá và cách xử lý gửi cho người dùng…" className="input !h-auto py-2" />
          <div className="flex items-start gap-2">
            <select aria-label="Trạng thái" value={status} onChange={(e) => setStatus(e.target.value as HelpStatus)} className="input !h-9 !w-auto">{SET.map((s) => <option key={s} value={s}>{HELP_STATUS_LABEL[s]}</option>)}</select>
            <button type="button" onClick={save} disabled={busy} className="btn-primary btn-sm">Lưu</button>
            {msg && <span className="self-center text-xs text-muted">{msg}</span>}
          </div>
        </div>
      )}
    </li>
  );
}
