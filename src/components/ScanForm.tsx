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

interface Props {
  authed: boolean;
  initialUrl?: string;
  autoStart?: boolean;
  size?: "lg" | "md";
  label?: string;
}

export function ScanForm({ authed, initialUrl = "", autoStart = false, size = "lg", label = "Quét website" }: Props) {
  const router = useRouter();
  const [url, setUrl] = useState(initialUrl);
  const [busy, setBusy] = useState(false);
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
      const res = await fetch("/api/scans", { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify({ url: value.trim() }) });
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
      <div className={`flex flex-col sm:flex-row gap-2 ${big ? "" : ""}`}>
        <label className="sr-only" htmlFor="scan-url">URL website</label>
        <input
          id="scan-url" name="url" type="text" inputMode="url" autoComplete="off" autoCapitalize="none" spellCheck={false}
          placeholder="example.com" value={url} onChange={(e) => setUrl(e.target.value)} disabled={busy}
          aria-invalid={!!error} aria-describedby={error ? "scan-error" : undefined}
          className={`flex-1 min-w-0 bg-surface border border-line-strong rounded-md px-4 text-fg placeholder:text-faint focus:border-fg/60 focus:outline-none ${big ? "h-14 text-lg" : "h-11 text-base"}`}
        />
        <button type="submit" disabled={busy}
          className={`rounded-md bg-fg text-bg font-medium hover:bg-white disabled:opacity-60 transition-colors ${big ? "h-14 px-7 text-base" : "h-11 px-5 text-sm"}`}>
          {busy ? "Đang bắt đầu…" : label}
        </button>
      </div>
      {error && <p id="scan-error" role="alert" className="mt-3 text-sm text-high">{error}</p>}
    </form>
  );
}
