"use client";
import { useState } from "react";

export function CopyButton({ text }: { text: string }) {
  const [done, setDone] = useState(false);
  return (
    <button
      type="button"
      onClick={async () => {
        try { await navigator.clipboard.writeText(text); setDone(true); setTimeout(() => setDone(false), 1500); } catch { /* clipboard unavailable */ }
      }}
      className="text-xs text-muted hover:text-fg px-2 py-1 rounded border border-line-strong"
    >
      {done ? "Copied" : "Copy"}
    </button>
  );
}
