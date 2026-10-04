"use client";
import { useRouter } from "next/navigation";
import { useState } from "react";

export function RescanButton({ url, variant = "primary", label = "Re-scan" }: { url: string; variant?: "primary" | "ghost"; label?: string }) {
  const router = useRouter();
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState<string | null>(null);
  return (
    <span className="inline-flex flex-col">
      <button
        type="button" disabled={busy}
        onClick={async () => {
          setBusy(true); setErr(null);
          const res = await fetch("/api/scans", { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify({ url }) });
          const body = await res.json().catch(() => ({}));
          if (res.ok) router.push(`/scans/${body.id}`);
          else { setErr(body.message ?? "Couldn't start the scan."); setBusy(false); }
        }}
        className={variant === "primary" ? "h-9 px-4 rounded-md bg-fg text-bg text-sm font-medium hover:bg-white disabled:opacity-60" : "h-9 px-4 rounded-md border border-line-strong text-sm hover:border-fg/50 disabled:opacity-60"}
      >
        {busy ? "Starting…" : label}
      </button>
      {err && <span role="alert" className="text-xs text-high mt-1 max-w-64">{err}</span>}
    </span>
  );
}
