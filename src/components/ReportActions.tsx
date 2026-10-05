"use client";
import { useRouter } from "next/navigation";
import { useState } from "react";
import { ConfirmDialog } from "./ConfirmDialog";
import { CopyButton } from "./CopyButton";
import { RescanButton } from "./RescanButton";

export function ReportActions({ scanId, url }: { scanId: string; url: string }) {
  const router = useRouter();
  const [share, setShare] = useState<string | null>(null);
  const [msg, setMsg] = useState<string | null>(null);
  const [confirmDel, setConfirmDel] = useState(false);
  const [busy, setBusy] = useState(false);

  async function createShare() {
    setMsg(null);
    const res = await fetch(`/api/scans/${scanId}/share`, { method: "POST" });
    const body = await res.json().catch(() => ({}));
    if (res.ok) setShare(body.url); else setMsg(body.message ?? "Không thể tạo liên kết.");
  }
  async function revoke() {
    const res = await fetch(`/api/scans/${scanId}/share`, { method: "DELETE" });
    if (res.ok) { setShare(null); setMsg("Đã thu hồi tất cả liên kết chia sẻ của báo cáo này."); }
  }
  async function del() {
    setBusy(true);
    const res = await fetch(`/api/scans/${scanId}`, { method: "DELETE" });
    if (res.ok) router.push("/dashboard");
    else { setMsg("Không thể xoá báo cáo."); setBusy(false); setConfirmDel(false); }
  }
  return (
    <div className="flex flex-col gap-3 lg:items-end">
      <div className="flex flex-wrap items-start gap-2 lg:justify-end">
        <RescanButton url={url} />
        <button className="btn-ghost btn-sm" onClick={createShare}>Chia sẻ (chỉ đọc)</button>
        <button className="btn-ghost btn-sm" onClick={revoke}>Thu hồi liên kết</button>
        <button className="btn-danger btn-sm" onClick={() => setConfirmDel(true)}>Xoá</button>
      </div>
      {share && (
        <div className="pop w-full max-w-md rounded-xl border border-accent/25 bg-accent-soft/60 p-3">
          <div className="flex items-center gap-2 rounded-lg border border-line bg-white p-1.5 pl-3">
            <code className="min-w-0 flex-1 truncate text-xs text-muted">{share}</code>
            <CopyButton text={share} />
          </div>
          <p className="mt-2 text-xs leading-relaxed text-muted">Bất kỳ ai có liên kết này đều xem được báo cáo. Liên kết chỉ hiển thị một lần, hãy sao chép ngay. Liên kết tuân theo thời gian lưu trữ bạn đã thiết lập.</p>
        </div>
      )}
      {msg && <p role="status" className="fade-in text-sm text-muted">{msg}</p>}
      <ConfirmDialog open={confirmDel} danger busy={busy} title="Xoá báo cáo này?" description="Báo cáo và các phát hiện sẽ bị xoá vĩnh viễn, mọi liên kết chia sẻ sẽ ngừng hoạt động. Không thể hoàn tác." confirmLabel="Xoá vĩnh viễn" onConfirm={del} onCancel={() => setConfirmDel(false)} />
    </div>
  );
}
