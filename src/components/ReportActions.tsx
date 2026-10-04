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
    if (res.ok) setShare(body.url); else setMsg(body.message ?? "Couldn't create a link.");
  }
  async function revoke() {
    const res = await fetch(`/api/scans/${scanId}/share`, { method: "DELETE" });
    if (res.ok) { setShare(null); setMsg("All share links for this report were revoked."); }
  }
  async function del() {
    if (!confirm("Delete this report permanently? Share links will stop working.")) return;
    const res = await fetch(`/api/scans/${scanId}`, { method: "DELETE" });
    if (res.ok) router.push("/dashboard"); else setMsg("Couldn't delete the report.");
  }
  const btn = "h-9 px-3 rounded-md border border-line-strong text-sm hover:border-fg/50";
  return (
    <div className="flex flex-col gap-3">
      <div className="flex flex-wrap items-start gap-2">
        <RescanButton url={url} />
        <button className={btn} onClick={createShare}>Share read-only link</button>
        <button className={btn} onClick={revoke}>Revoke links</button>
        <button className={`${btn} text-high hover:border-high/60`} onClick={del}>Delete</button>
      </div>
      {share && (
        <div className="flex items-center gap-2 text-sm bg-surface border border-line rounded-md p-2 pl-3">
          <code className="truncate flex-1 text-muted">{share}</code>
          <CopyButton text={share} />
        </div>
      )}
      {share && <p className="text-xs text-muted">Anyone with this link can view this report. It is shown once — copy it now. It follows your retention setting.</p>}
      {msg && <p role="status" className="text-sm text-muted">{msg}</p>}
    </div>
  );
}
