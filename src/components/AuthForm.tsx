"use client";
import Link from "next/link";
import { useRouter, useSearchParams } from "next/navigation";
import { useEffect, useRef, useState } from "react";

function safeNext(raw: string | null): string {
  return raw && raw.startsWith("/") && !raw.startsWith("//") && !raw.includes("\\") ? raw : "/dashboard";
}

const OAUTH_ERRORS: Record<string, string> = {
  access_denied: "Bạn đã huỷ đăng nhập bằng Google.",
  state_mismatch: "Phiên đăng nhập không hợp lệ. Vui lòng thử lại.",
  state_expired: "Phiên đăng nhập đã hết hạn. Vui lòng thử lại.",
  token_exchange: "Không thể hoàn tất đăng nhập với Google. Vui lòng thử lại.",
  invalid_token: "Không xác minh được danh tính từ Google. Vui lòng thử lại.",
  email_unverified: "Email Google của bạn chưa được xác minh nên không thể dùng để đăng nhập.",
  not_configured: "Đăng nhập bằng Google chưa được bật trên máy chủ này.",
  throttled: "Có quá nhiều lần thử. Vui lòng đợi vài phút rồi thử lại.",
  blocked: "Tài khoản này đang bị tạm khoá do hoạt động bất thường.",
};

const GoogleG = () => (
  <svg viewBox="0 0 24 24" className="size-[18px]" aria-hidden>
    <path fill="#4285F4" d="M23.5 12.27c0-.85-.08-1.67-.22-2.45H12v4.64h6.45a5.52 5.52 0 0 1-2.4 3.62v3h3.88c2.27-2.09 3.57-5.17 3.57-8.81Z" />
    <path fill="#34A853" d="M12 24c3.24 0 5.96-1.07 7.95-2.91l-3.88-3a7.2 7.2 0 0 1-10.74-3.78H1.3v3.09A12 12 0 0 0 12 24Z" />
    <path fill="#FBBC05" d="M5.33 14.31a7.2 7.2 0 0 1 0-4.62V6.6H1.3a12 12 0 0 0 0 10.8l4.03-3.09Z" />
    <path fill="#EA4335" d="M12 4.77c1.76 0 3.34.61 4.59 1.8l3.44-3.44A11.98 11.98 0 0 0 1.3 6.6l4.03 3.09A7.2 7.2 0 0 1 12 4.77Z" />
  </svg>
);

/** Turnstile (tuỳ chọn). Chỉ gắn khi NEXT_PUBLIC_TURNSTILE_SITE_KEY có giá trị. */
function TurnstileWidget({ siteKey, onToken }: { siteKey: string; onToken: (t: string | undefined) => void }) {
  const ref = useRef<HTMLDivElement>(null);
  useEffect(() => {
    const w = window as unknown as { turnstile?: { render: (el: HTMLElement, o: Record<string, unknown>) => string; remove: (id: string) => void } };
    let id: string | undefined;
    const mount = () => { if (ref.current && w.turnstile && !id) id = w.turnstile.render(ref.current, { sitekey: siteKey, theme: "light", callback: onToken, "expired-callback": () => onToken(undefined) }); };
    if (w.turnstile) mount();
    else {
      const s = document.createElement("script");
      s.src = "https://challenges.cloudflare.com/turnstile/v0/api.js?render=explicit";
      s.async = true; s.onload = mount;
      document.head.appendChild(s);
    }
    return () => { if (id && w.turnstile) w.turnstile.remove(id); };
  }, [siteKey, onToken]);
  return <div ref={ref} />;
}

export function AuthForm({ mode, googleEnabled }: { mode: "login" | "signup"; googleEnabled: boolean }) {
  const router = useRouter();
  const params = useSearchParams();
  const next = safeNext(params.get("next"));
  const oauthError = params.get("error");
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [busy, setBusy] = useState(false);
  const [googleBusy, setGoogleBusy] = useState(false);
  const [error, setError] = useState<string | null>(oauthError ? (OAUTH_ERRORS[oauthError] ?? "Đăng nhập không thành công. Vui lòng thử lại.") : null);
  const [turnstile, setTurnstile] = useState<string | undefined>();
  const siteKey = process.env.NEXT_PUBLIC_TURNSTILE_SITE_KEY;
  const isLogin = mode === "login";

  async function submit(e: React.FormEvent) {
    e.preventDefault();
    setBusy(true); setError(null);
    try {
      const res = await fetch(`/api/auth/${mode}`, { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify({ email, password, turnstile }) });
      const body = await res.json().catch(() => ({}));
      if (!res.ok) { setError(body.message ?? "Đã xảy ra lỗi. Vui lòng thử lại."); setBusy(false); return; }
      router.push(next); router.refresh();
    } catch {
      setError("Lỗi mạng. Vui lòng thử lại."); setBusy(false);
    }
  }

  return (
    <div className="container-x grid min-h-[calc(100dvh-3.5rem-1px)] items-center gap-12 py-12 lg:grid-cols-[1.1fr_1fr] lg:gap-20">
      {/* bên trái: giá trị + motif terminal */}
      <div className="reveal hidden lg:block" style={{ ["--i" as string]: 0 }}>
        <p className="eyebrow">// kiểm tra bảo mật từ bên ngoài</p>
        <h2 className="mt-4 max-w-md text-4xl font-semibold leading-[1.1] tracking-tight">Biết trước kẻ tấn công thấy gì ở website của bạn.</h2>
        <div className="term mt-10 max-w-md">
          <div className="term-bar"><span className="term-dot" /><span className="term-dot" /><span className="term-dot" /><span className="ml-1">vibesec ~ scan</span></div>
          <div className="term-body">
            <p><span className="prompt">$</span> vibesec scan example.com</p>
            <p className="text-ok">✓ HTTPS &amp; TLS đạt</p>
            <p className="text-med">! Thiếu Content-Security-Policy</p>
            <p className="text-ok">✓ Không lộ khoá bí mật</p>
            <p className="text-muted">→ điểm 87/100 · hạng B<span className="cursor" /></p>
          </div>
        </div>
      </div>

      <div className="reveal mx-auto w-full max-w-sm" style={{ ["--i" as string]: 1 }}>
        <h1 className="text-2xl font-semibold tracking-tight">{isLogin ? "Đăng nhập" : "Tạo tài khoản"}</h1>
        <p className="mt-2 text-sm text-muted">{isLogin ? "Truy cập lịch sử quét và báo cáo của bạn." : "Tài khoản giúp chống lạm dụng công cụ quét và cho phép theo dõi điểm theo thời gian."}</p>

        {error && (
          <div role="alert" className="pop mt-6 flex gap-2.5 rounded-lg border border-crit/25 bg-crit/5 px-3.5 py-3 text-sm text-crit">
            <svg viewBox="0 0 24 24" className="mt-0.5 size-4 shrink-0" fill="none" stroke="currentColor" strokeWidth="2.2" strokeLinecap="round"><circle cx="12" cy="12" r="9" /><path d="M12 8v5M12 16.5v.01" /></svg>
            <span>{error}</span>
          </div>
        )}

        <div className="mt-6">
          {googleEnabled ? (
            <a href={`/api/auth/google?next=${encodeURIComponent(next)}`} onClick={() => setGoogleBusy(true)} aria-busy={googleBusy}
              className="btn-ghost btn-lg w-full gap-3 text-[15px]">
              {googleBusy ? <span className="live-dot" aria-hidden /> : <GoogleG />}
              {googleBusy ? "Đang chuyển tới Google…" : isLogin ? "Đăng nhập bằng Google" : "Đăng ký bằng Google"}
            </a>
          ) : (
            <div className="rounded-xl border border-dashed border-line-strong bg-surface px-4 py-3 text-sm text-muted">
              <p className="flex items-center gap-2 font-medium text-fg"><GoogleG />Đăng nhập Google chưa được bật</p>
              <p className="mt-1 text-xs">Quản trị viên cần cấu hình <span className="mono">GOOGLE_CLIENT_ID</span> và <span className="mono">GOOGLE_CLIENT_SECRET</span> trên máy chủ.</p>
            </div>
          )}
        </div>

        <div className="my-6 flex items-center gap-3 text-xs text-faint" aria-hidden><span className="h-px flex-1 bg-line" />hoặc dùng email<span className="h-px flex-1 bg-line" /></div>

        <form onSubmit={submit} className="space-y-4">
          <label className="block text-sm font-medium">Email
            <input className="input mt-1.5" type="email" required autoComplete="email" value={email} onChange={(e) => setEmail(e.target.value)} />
          </label>
          <label className="block text-sm font-medium">Mật khẩu
            <input className="input mt-1.5" type="password" required minLength={10} autoComplete={isLogin ? "current-password" : "new-password"} value={password} onChange={(e) => setPassword(e.target.value)} />
            {!isLogin && <span className="mt-1.5 block text-xs font-normal text-muted">Từ 10 ký tự trở lên, không dùng mật khẩu quá phổ biến.</span>}
          </label>
          {siteKey && <TurnstileWidget siteKey={siteKey} onToken={setTurnstile} />}
          <button disabled={busy} className="btn-dark btn-lg w-full">{busy ? <><span className="live-dot !bg-white" aria-hidden />Vui lòng đợi…</> : isLogin ? "Đăng nhập" : "Tạo tài khoản"}</button>
        </form>

        <p className="mt-6 text-sm text-muted">
          {isLogin ? <>Chưa có tài khoản? <Link className="font-medium text-accent hover:underline" href={`/signup?next=${encodeURIComponent(next)}`}>Đăng ký</Link></> : <>Đã có tài khoản? <Link className="font-medium text-accent hover:underline" href={`/login?next=${encodeURIComponent(next)}`}>Đăng nhập</Link></>}
        </p>
        <p className="mt-6 text-xs leading-relaxed text-faint">Chúng tôi chỉ lưu email, tên và ảnh đại diện từ Google. Không bao giờ truy cập Gmail, Drive hay danh bạ của bạn.</p>
      </div>
    </div>
  );
}
