"use client";

import { useEffect, useState } from "react";
import { useMatMat } from "./matmat/MatMatProvider";

type Phase = "ask" | "unclear-form" | "thanks";
const storeKey = (rule: string, variant: string) => `vibesec-clarity:${rule}:${variant}`;

/**
 * "Giải thích này có rõ không?" — thu dữ liệu thật về mục nào khó hiểu. Không cần đăng nhập, không gửi tên miền hay URL.
 * Nhớ lựa chọn ở trình duyệt để không hỏi lại; có thể đổi ý.
 */
export function ClarityVote({ ruleId, variant, source }: { ruleId: string; variant: string; source: "quick" | "full" }) {
  const { mode } = useMatMat();
  const [phase, setPhase] = useState<Phase>("ask");
  const [verdict, setVerdict] = useState<"clear" | "unclear" | null>(null);
  const [comment, setComment] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");

  useEffect(() => {
    setPhase("ask"); setVerdict(null); setComment(""); setError("");
    try { const v = localStorage.getItem(storeKey(ruleId, variant)); if (v === "clear" || v === "unclear") { setVerdict(v); setPhase("thanks"); } } catch { /* không đọc được localStorage */ }
  }, [ruleId, variant]);

  async function send(v: "clear" | "unclear", c = "") {
    setBusy(true); setError("");
    try {
      const res = await fetch("/api/explain-feedback", { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify({ ruleId, variant, verdict: v, source, mode, comment: c }) });
      if (!res.ok) { setError(((await res.json().catch(() => null)) as { message?: string } | null)?.message ?? "Chưa gửi được. Vui lòng thử lại."); setBusy(false); return; }
      try { localStorage.setItem(storeKey(ruleId, variant), v); } catch { /* bỏ qua */ }
      setVerdict(v); setPhase("thanks");
    } catch { setError("Lỗi mạng. Vui lòng thử lại."); }
    setBusy(false);
  }

  if (phase === "thanks") {
    return (
      <p className="mt-4 text-[13px] text-muted" aria-live="polite">
        {verdict === "clear" ? "Cảm ơn bạn! Rất vui vì giải thích này dễ hiểu." : "Cảm ơn bạn! Chúng tôi sẽ viết lại mục này cho rõ hơn."}{" "}
        <button type="button" onClick={() => setPhase("ask")} className="text-accent hover:underline">Đổi đánh giá</button>
      </p>
    );
  }
  if (phase === "unclear-form") {
    return (
      <div className="mt-4 rounded-xl border border-line bg-surface p-3.5">
        <label htmlFor={`clr-${ruleId}`} className="text-sm font-medium">Chỗ nào chưa rõ? <span className="font-normal text-faint">(không bắt buộc)</span></label>
        <textarea id={`clr-${ruleId}`} rows={2} maxLength={300} value={comment} onChange={(e) => setComment(e.target.value)} placeholder="Ví dụ: mình không hiểu “clickjacking” nghĩa là gì…" className="input mt-2 !h-auto resize-none py-2 text-sm" />
        {error && <p role="alert" className="mt-1.5 text-xs text-crit">{error}</p>}
        <div className="mt-2.5 flex gap-2">
          <button type="button" disabled={busy} onClick={() => void send("unclear", comment)} className="btn-primary btn-sm">Gửi</button>
          <button type="button" disabled={busy} onClick={() => setPhase("ask")} className="btn-ghost btn-sm">Quay lại</button>
        </div>
      </div>
    );
  }
  return (
    <div className="mt-4 flex flex-wrap items-center gap-2 text-[13px]" role="group" aria-label="Đánh giá độ rõ của giải thích">
      <span className="text-muted">Giải thích này có rõ không?</span>
      <button type="button" disabled={busy} onClick={() => void send("clear")} className="btn-ghost btn-sm">👍 Có</button>
      <button type="button" disabled={busy} onClick={() => setPhase("unclear-form")} className="btn-ghost btn-sm">🤔 Chưa</button>
      {error && <span role="alert" className="text-xs text-crit">{error}</span>}
    </div>
  );
}
