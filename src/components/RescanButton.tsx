"use client";
import { useRouter } from "next/navigation";
import { useState } from "react";

export function RescanButton({ url, variant = "primary", label = "Quét lại" }: { url: string; variant?: "primary" | "ghost"; label?: string }) {
  const router = useRouter();
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState<string | null>(null);
  return (
    <span className="inline-flex flex-col">
      <button
        type="button" disabled={busy}
        onClick={async () => {
          setBusy(true); setErr(null);
          try {
            const res = await fetch("/api/scans", { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify({ url }) });
            const body = await res.json().catch(() => ({}));
            if (res.ok) router.push(`/scans/${body.id}`);
            else { setErr(body.message ?? "Không thể bắt đầu lượt quét."); setBusy(false); }
          } catch { setErr("Lỗi mạng. Vui lòng thử lại."); setBusy(false); }
        }}
        className={`${variant === "primary" ? "btn-primary" : "btn-ghost"} btn-sm`}
      >
        {busy ? <><span className="live-dot" aria-hidden />Đang bắt đầu…</> : <><svg viewBox="0 0 24 24" className="size-3.5" fill="none" stroke="currentColor" strokeWidth="2.2" strokeLinecap="round" strokeLinejoin="round" aria-hidden><path d="M3 12a9 9 0 0 1 15.5-6.2L21 8M21 3v5h-5M21 12a9 9 0 0 1-15.5 6.2L3 16M3 21v-5h5" /></svg>{label}</>}
      </button>
      {err && <span role="alert" className="mt-1 max-w-64 text-xs text-crit">{err}</span>}
    </span>
  );
}
