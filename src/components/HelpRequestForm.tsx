"use client";

import { useRouter } from "next/navigation";
import { useState } from "react";
import { SEV_CHIP } from "@/lib/format";
import { SEV_LABEL } from "@/lib/i18n";
import type { Severity } from "@/lib/scanner/types";

interface Issue { fingerprint: string; title: string; severity: Severity; group: string }
interface Props { kind: string; id: string; label: string; issues: Issue[]; email: string }

/** Gửi yêu cầu nhờ đội kỹ thuật xử lý các lỗi đã chọn. Người dùng thấy rõ họ chia sẻ gì. */
export function HelpRequestForm({ kind, id, label, issues, email }: Props) {
  const router = useRouter();
  const [sel, setSel] = useState<Set<string>>(new Set(issues.filter((i) => i.severity === "critical" || i.severity === "high").map((i) => i.fingerprint)));
  const [note, setNote] = useState("");
  const [contact, setContact] = useState("");
  const [consent, setConsent] = useState(false);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const toggle = (f: string) => setSel((s) => { const n = new Set(s); if (n.has(f)) n.delete(f); else n.add(f); return n; });

  async function submit() {
    setError(null);
    if (!sel.size) return setError("Hãy chọn ít nhất một lỗi cần xử lý.");
    if (!consent) return setError("Hãy đồng ý chia sẻ các mục đã chọn với đội kỹ thuật.");
    setBusy(true);
    try {
      const res = await fetch("/api/help-requests", { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify({ kind, id, fingerprints: [...sel], note, contact, consent }) });
      const out = await res.json().catch(() => ({}));
      if (!res.ok) { setError(out.message ?? "Đã xảy ra lỗi. Vui lòng thử lại."); setBusy(false); return; }
      router.push("/nho-chuyen-gia?sent=1"); router.refresh();
    } catch { setError("Lỗi mạng. Vui lòng thử lại."); setBusy(false); }
  }

  return (
    <form onSubmit={(e) => { e.preventDefault(); void submit(); }} noValidate className="max-w-3xl">
      <p className="eyebrow">1 · chọn lỗi cần chuyên gia xử lý — <span className="mono normal-case">{label}</span></p>
      <ul className="panel mt-2 divide-y divide-line">
        {issues.map((i) => (
          <li key={i.fingerprint}>
            <label className="flex cursor-pointer items-start gap-3 px-4 py-3 transition-colors hover:bg-surface">
              <input type="checkbox" checked={sel.has(i.fingerprint)} onChange={() => toggle(i.fingerprint)} disabled={busy} className="mt-1 size-4 accent-[var(--color-accent)]" />
              <span className="min-w-0 flex-1"><span className="block leading-snug">{i.title}</span><span className="text-xs text-muted">{i.group}</span></span>
              <span className={`${SEV_CHIP[i.severity]} shrink-0`}>{SEV_LABEL[i.severity]}</span>
            </label>
          </li>
        ))}
      </ul>
      <div className="mt-5">
        <label htmlFor="help-note" className="mb-1 block text-[13px] font-medium">2 · Bạn muốn chúng tôi giúp gì? (tuỳ chọn)</label>
        <textarea id="help-note" value={note} onChange={(e) => setNote(e.target.value)} maxLength={1000} rows={3} disabled={busy} placeholder="Ví dụ: cần sửa trước ngày 15/10, dự án dùng Next.js + Supabase…" className="input !h-auto py-2.5" />
      </div>
      <div className="mt-4">
        <label htmlFor="help-contact" className="mb-1 block text-[13px] font-medium">3 · Cách liên hệ thêm (Zalo/SĐT, tuỳ chọn)</label>
        <input id="help-contact" value={contact} onChange={(e) => setContact(e.target.value)} maxLength={120} disabled={busy} placeholder={`Mặc định: ${email}`} className="input" />
      </div>
      <div className="panel-soft mt-5 p-4 text-[14px] leading-relaxed text-muted">
        <p className="font-medium text-fg">Đội kỹ thuật sẽ nhận được</p>
        <p className="mt-1">Tên lỗi, mức độ, vị trí (đã ẩn giá trị bí mật) của các mục bạn chọn, kèm ghi chú và cách liên hệ. Họ <strong className="font-medium text-fg">không</strong> nhận khoá, token hay mật khẩu. Chúng tôi phản hồi kèm báo giá; chưa tính phí cho đến khi bạn đồng ý.</p>
      </div>
      <label className="mt-4 flex cursor-pointer items-start gap-2 text-sm text-muted">
        <input type="checkbox" checked={consent} onChange={(e) => setConsent(e.target.checked)} disabled={busy} className="mt-0.5 size-4 accent-[var(--color-accent)]" />
        <span>Tôi đồng ý chia sẻ các mục đã chọn ở trên với đội kỹ thuật VibeSec để được tư vấn xử lý.</span>
      </label>
      <button type="submit" disabled={busy} className="btn-primary btn-lg mt-5">{busy ? <><span className="live-dot !bg-white" aria-hidden />Đang gửi…</> : `Gửi yêu cầu (${sel.size} lỗi)`}</button>
      {error && <p role="alert" className="pop mt-3 text-sm text-crit">{error}</p>}
    </form>
  );
}
