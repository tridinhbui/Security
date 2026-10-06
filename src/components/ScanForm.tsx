"use client";

import { useRouter } from "next/navigation";
import { useEffect, useRef, useState } from "react";

const ERRORS: Record<string, string> = {
  invalid_url: "Địa chỉ website này không hợp lệ.",
  scheme_not_allowed: "Chỉ có thể quét địa chỉ http và https.",
  internal_hostname: "Không thể quét tên miền nội bộ hoặc cục bộ. Hãy nhập một website công khai.",
  non_public_ip: "Địa chỉ này không truy cập được từ bên ngoài nên không thể quét.",
  port_not_allowed: "Chỉ có thể quét các cổng web tiêu chuẩn (80 và 443).",
  credentials_not_allowed: "Hãy xoá tên người dùng/mật khẩu khỏi URL.",
  dns_failed: "Chúng tôi không tìm thấy tên miền này. Hãy kiểm tra lại chính tả.",
};

interface Props { authed: boolean; initialUrl?: string; autoStart?: boolean; size?: "lg" | "md"; label?: string; /** Cố định kiểu quét (ẩn ô chọn): "basic" = quét nhanh, "advanced" = quét đầy đủ. */ mode?: "basic" | "advanced" }

/**
 * Ô nhập mục tiêu. Kiểm tra phía client chỉ để phản hồi nhanh; MỌI quy tắc an toàn (SSRF, cổng, giao thức)
 * được kiểm tra lại ở máy chủ và không bao giờ tin giá trị từ trình duyệt.
 */
export function ScanForm({ authed, initialUrl = "", autoStart = false, size = "lg", label = "Quét ngay", mode }: Props) {
  const router = useRouter();
  const [url, setUrl] = useState(initialUrl);
  const [busy, setBusy] = useState(false);
  const [quickPick, setQuick] = useState(false);
  const quick = mode ? mode === "basic" : quickPick;
  const [error, setError] = useState<string | null>(null);
  const started = useRef(false);

  async function submit(value: string) {
    if (!value.trim()) return setError("Hãy nhập địa chỉ website, ví dụ example.com");
    if (!authed) {
      router.push(`/login?next=${encodeURIComponent(`/dashboard?scan=${encodeURIComponent(value.trim())}`)}`);
      return;
    }
    setBusy(true);
    setError(null);
    try {
      const res = await fetch("/api/scans", { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify({ url: value.trim(), quick }) });
      const body = await res.json().catch(() => ({}));
      if (res.status === 401) return router.push(`/login?next=/dashboard`);
      if (!res.ok) {
        setError(body.message ?? ERRORS[body.error] ?? "Đã xảy ra lỗi. Vui lòng thử lại.");
        setBusy(false);
        return;
      }
      router.push(`/scans/${body.id}`);
    } catch {
      setError("Lỗi mạng. Vui lòng thử lại.");
      setBusy(false);
    }
  }

  useEffect(() => {
    if (autoStart && initialUrl && !started.current) {
      started.current = true;
      void submit(initialUrl);
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  const big = size === "lg";
  return (
    <form onSubmit={(e) => { e.preventDefault(); void submit(url); }} noValidate className="w-full">
      <div className={`flex flex-col gap-2 rounded-2xl border bg-white p-2 shadow-glow transition-[border-color,box-shadow] duration-200 focus-within:border-accent focus-within:ring-4 focus-within:ring-accent/15 sm:flex-row sm:items-center ${error ? "border-crit/50" : "border-line-strong"}`}>
        <label className="sr-only" htmlFor="scan-url">URL website</label>
        <div className="flex min-w-0 flex-1 items-center gap-3 px-3">
          <svg viewBox="0 0 24 24" className="size-5 shrink-0 text-fg" fill="none" stroke="currentColor" strokeWidth="1.8" strokeLinecap="round" strokeLinejoin="round" aria-hidden><path d="m5 8 5 4-5 4" /><path d="M13 17h6" /></svg>
          <input
            id="scan-url" name="url" type="text" inputMode="url" autoComplete="off" autoCapitalize="none" spellCheck={false}
            placeholder="Nhập URL để quét (ví dụ: https://example.com)" value={url} onChange={(e) => setUrl(e.target.value)} disabled={busy} maxLength={2048}
            aria-invalid={!!error} aria-describedby={error ? "scan-error" : undefined}
            className={`min-w-0 flex-1 bg-transparent text-fg placeholder:text-faint focus:outline-none ${big ? "h-12 text-[15px]" : "h-10 text-[15px]"}`}
          />
        </div>
        <button type="submit" disabled={busy} className={`btn-primary ${big ? "btn-lg" : ""} sm:min-w-36`}>
          {busy ? <><span className="live-dot !bg-white" aria-hidden />Đang bắt đầu…</> : <>{label}<svg viewBox="0 0 24 24" className="size-4" fill="none" stroke="currentColor" strokeWidth="2.2" strokeLinecap="round" strokeLinejoin="round" aria-hidden><path d="M5 12h14M13 6l6 6-6 6" /></svg></>}
        </button>
      </div>
      {authed && !mode && (
        <label className="mt-3 flex cursor-pointer items-start gap-2 text-sm text-muted">
          <input type="checkbox" checked={quick} onChange={(e) => setQuick(e.target.checked)} disabled={busy} className="mt-0.5 size-4 accent-[var(--color-accent)]" />
          <span><span className="font-medium text-fg">Quét nhanh</span> — bỏ qua việc tải và phân tích file JavaScript (nhẹ hơn, ít sâu hơn). Bỏ chọn để quét đầy đủ.</span>
        </label>
      )}
      {error && <p id="scan-error" role="alert" className="pop mt-3 flex items-start gap-2 text-sm text-crit"><svg viewBox="0 0 24 24" className="mt-0.5 size-4 shrink-0" fill="none" stroke="currentColor" strokeWidth="2.2" strokeLinecap="round" aria-hidden><circle cx="12" cy="12" r="9" /><path d="M12 8v5M12 16.5v.01" /></svg>{error}</p>}
    </form>
  );
}
