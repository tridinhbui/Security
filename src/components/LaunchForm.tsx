"use client";

import Link from "next/link";
import { useRouter } from "next/navigation";
import { useState } from "react";
import { formatDate } from "@/lib/format";

interface Opt { id: string; label: string; at: string; note?: string }
interface Props { websites: Opt[]; codes: Opt[]; systems: Opt[] }

/** Chọn kết quả quét của từng phần rồi đánh giá. Không quét thêm: chỉ tổng hợp những gì bạn đã quét. */
export function LaunchForm({ websites, codes, systems }: Props) {
  const router = useRouter();
  const [website, setWebsite] = useState(websites[0]?.id ?? "");
  const [code, setCode] = useState(codes[0]?.id ?? "");
  const [system, setSystem] = useState(systems[0]?.id ?? "");
  const [label, setLabel] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);

  async function submit() {
    setError(null);
    if (!website && !code && !system) return setError("Hãy chọn ít nhất một kết quả quét, hoặc quét trước ở các trang bên trái.");
    setBusy(true);
    try {
      const res = await fetch("/api/project-scans/launch", { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify({
        label: label.trim() || undefined, websiteScanId: website || undefined,
        codeId: code && code !== "skip" ? code : undefined, systemId: system && system !== "skip" ? system : undefined,
        skip: [...(code === "skip" ? ["code"] : []), ...(system === "skip" ? ["system"] : [])],
      }) });
      const out = await res.json().catch(() => ({}));
      if (res.status === 401) return router.push("/login?next=/truoc-ra-mat");
      if (!res.ok) { setError(out.message ?? "Đã xảy ra lỗi. Vui lòng thử lại."); setBusy(false); return; }
      router.push(`/truoc-ra-mat/${out.id}`);
    } catch { setError("Lỗi mạng. Vui lòng thử lại."); setBusy(false); }
  }

  const row = (title: string, value: string, set: (v: string) => void, opts: Opt[], href: string, skippable: boolean, none: string) => (
    <div className="panel p-4">
      <div className="flex items-center justify-between gap-3">
        <label htmlFor={`pick-${title}`} className="font-medium">{title}</label>
        <Link href={href} className="text-[13px] font-medium text-accent hover:underline">{opts.length ? "Quét mới →" : "Quét ngay →"}</Link>
      </div>
      {opts.length || skippable ? (
        <select id={`pick-${title}`} value={value} onChange={(e) => set(e.target.value)} disabled={busy} className="input mt-2">
          {!opts.length && <option value="">{none}</option>}
          {opts.map((o) => <option key={o.id} value={o.id}>{o.label} · {formatDate(o.at)}{o.note ? ` · ${o.note}` : ""}</option>)}
          {skippable && <option value="skip">Không áp dụng cho dự án này</option>}
          {!skippable && <option value="">Bỏ qua phần này (sẽ ghi là chưa kiểm tra)</option>}
        </select>
      ) : <p className="mt-2 text-[14px] text-muted">{none}</p>}
    </div>
  );

  return (
    <form onSubmit={(e) => { e.preventDefault(); void submit(); }} noValidate className="max-w-3xl">
      <div className="space-y-3">
        {row("Website", website, setWebsite, websites, "/quet-nang-cao", false, "Chưa có lượt quét website nào hoàn tất.")}
        {row("Mã nguồn", code, setCode, codes, "/quet-ma-nguon", true, "Chưa có lượt quét mã nguồn nào.")}
        {row("Hệ thống (database, storage, đăng nhập)", system, setSystem, systems, "/quet-he-thong", true, "Chưa có lượt quét hệ thống nào.")}
      </div>
      <div className="mt-4">
        <label htmlFor="launch-label" className="mb-1 block text-[13px] font-medium">Tên dự án (tuỳ chọn)</label>
        <input id="launch-label" value={label} onChange={(e) => setLabel(e.target.value)} maxLength={80} disabled={busy} placeholder="Để trống: dùng tên website" className="input" />
        <p className="mt-1 text-[12.5px] text-muted">Các lần đánh giá cùng tên được so sánh Trước / Sau với nhau.</p>
      </div>
      <button type="submit" disabled={busy} className="btn-primary btn-lg mt-5">
        {busy ? <><span className="live-dot !bg-white" aria-hidden />Đang tổng hợp…</> : <>Đánh giá sẵn sàng ra mắt<svg viewBox="0 0 24 24" className="size-4" fill="none" stroke="currentColor" strokeWidth="2.2" strokeLinecap="round" strokeLinejoin="round" aria-hidden><path d="M5 12h14M13 6l6 6-6 6" /></svg></>}
      </button>
      {error && <p role="alert" className="pop mt-3 text-sm text-crit">{error}</p>}
    </form>
  );
}
