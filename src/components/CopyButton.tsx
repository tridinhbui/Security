"use client";
import { useState } from "react";

export function CopyButton({ text }: { text: string }) {
  const [done, setDone] = useState(false);
  return (
    <button
      type="button"
      onClick={async () => {
        try { await navigator.clipboard.writeText(text); setDone(true); setTimeout(() => setDone(false), 1600); } catch { /* clipboard không khả dụng */ }
      }}
      aria-label={done ? "Đã sao chép" : "Sao chép"}
      className={`inline-flex h-7 items-center gap-1.5 rounded-md border px-2 text-[11px] font-medium shadow-crisp transition-colors ${done ? "border-ok/30 bg-ok/5 text-ok" : "border-line-strong bg-white text-muted hover:border-fg/40 hover:text-fg"}`}
    >
      {done ? <svg viewBox="0 0 24 24" className="pop size-3" fill="none" stroke="currentColor" strokeWidth="3" strokeLinecap="round" strokeLinejoin="round"><path d="m5 12.5 4.5 4.5L19 7.5" /></svg> : <svg viewBox="0 0 24 24" className="size-3" fill="none" stroke="currentColor" strokeWidth="2.2" strokeLinecap="round" strokeLinejoin="round"><rect x="9" y="9" width="11" height="11" rx="2" /><path d="M5 15V6a2 2 0 0 1 2-2h9" /></svg>}
      {done ? "Đã chép" : "Chép"}
    </button>
  );
}
