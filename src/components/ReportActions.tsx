"use client";
import { useRouter } from "next/navigation";
import { useState } from "react";
import { CopyButton } from "./CopyButton";
import { RescanButton } from "./RescanButton";

export function ReportActions({ scanId, url }: { scanId: string; url: string }) {
  const router = useRouter();
  const [share, setShare] = useState<string | null>(null);
  const [msg, setMsg] = useState<string | null>(null);

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
    if (!confirm("Xoá vĩnh viễn báo cáo này? Các liên kết chia sẻ sẽ không còn hoạt động.")) return;
    const res = await fetch(`/api/scans/${scanId}`, { method: "DELETE" });
    if (res.ok) router.push("/dashboard"); else setMsg("Không thể xoá báo cáo.");
  }
  const btn = "h-9 px-3 rounded-md border border-line-strong text-sm hover:border-fg/50";
  return (
    <div className="flex flex-col gap-3">
      <div className="flex flex-wrap items-start gap-2">
        <RescanButton url={url} />
        <button className={btn} onClick={createShare}>Tạo liên kết chia sẻ chỉ đọc</button>
        <button className={btn} onClick={revoke}>Thu hồi liên kết</button>
        <button className={`${btn} text-high hover:border-high/60`} onClick={del}>Xoá</button>
      </div>
      {share && (
        <div className="flex items-center gap-2 text-sm bg-surface border border-line rounded-md p-2 pl-3">
          <code className="truncate flex-1 text-muted">{share}</code>
          <CopyButton text={share} />
        </div>
      )}
      {share && <p className="text-xs text-muted">Bất kỳ ai có liên kết này đều xem được báo cáo. Liên kết chỉ hiển thị một lần, hãy sao chép ngay. Liên kết tuân theo thời gian lưu trữ bạn đã thiết lập.</p>}
      {msg && <p role="status" className="text-sm text-muted">{msg}</p>}
    </div>
  );
}
