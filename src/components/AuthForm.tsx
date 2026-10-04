"use client";
import Link from "next/link";
import { useRouter, useSearchParams } from "next/navigation";
import { useEffect, useRef, useState } from "react";

function safeNext(raw: string | null): string {
  return raw && raw.startsWith("/") && !raw.startsWith("//") && !raw.includes("\\") ? raw : "/dashboard";
}

/** Cloudflare Turnstile widget (explicit render). Only mounted when NEXT_PUBLIC_TURNSTILE_SITE_KEY is set. */
function TurnstileWidget({ siteKey, onToken }: { siteKey: string; onToken: (t: string | undefined) => void }) {
  const ref = useRef<HTMLDivElement>(null);
  useEffect(() => {
    const w = window as unknown as { turnstile?: { render: (el: HTMLElement, o: Record<string, unknown>) => string; remove: (id: string) => void } };
    let id: string | undefined;
    const mount = () => { if (ref.current && w.turnstile && !id) id = w.turnstile.render(ref.current, { sitekey: siteKey, theme: "dark", callback: onToken, "expired-callback": () => onToken(undefined) }); };
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

export function AuthForm({ mode }: { mode: "login" | "signup" }) {
  const router = useRouter();
  const params = useSearchParams();
  const next = safeNext(params.get("next"));
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [turnstile, setTurnstile] = useState<string | undefined>();
  const siteKey = process.env.NEXT_PUBLIC_TURNSTILE_SITE_KEY;
  

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

  const input = "w-full h-11 bg-surface border border-line-strong rounded-md px-3 focus:border-fg/60 focus:outline-none";
  return (
    <div className="mx-auto max-w-sm px-5 py-20">
      <h1 className="text-2xl font-semibold tracking-tight">{mode === "login" ? "Đăng nhập" : "Tạo tài khoản của bạn"}</h1>
      <p className="mt-2 text-sm text-muted">{mode === "login" ? "Truy cập lịch sử quét và các báo cáo của bạn." : "Tài khoản giúp ngăn việc lạm dụng công cụ quét và cho phép bạn theo dõi điểm số theo thời gian."}</p>
      <form onSubmit={submit} className="mt-8 space-y-4">
        <label className="block text-sm">Email
          <input className={`${input} mt-1.5`} type="email" required autoComplete="email" value={email} onChange={(e) => setEmail(e.target.value)} />
        </label>
        <label className="block text-sm">Mật khẩu
          <input className={`${input} mt-1.5`} type="password" required minLength={10} autoComplete={mode === "login" ? "current-password" : "new-password"} value={password} onChange={(e) => setPassword(e.target.value)} />
        </label>
        {siteKey && <TurnstileWidget siteKey={siteKey} onToken={setTurnstile} />}
        {error && <p role="alert" className="text-sm text-high">{error}</p>}
        
        <button disabled={busy} className="w-full h-11 rounded-md bg-fg text-bg font-medium hover:bg-white disabled:opacity-60">{busy ? "Vui lòng chờ…" : mode === "login" ? "Đăng nhập" : "Tạo tài khoản"}</button>
      </form>
      <p className="mt-6 text-sm text-muted">
        {mode === "login" ? <>Chưa có tài khoản? <Link className="underline underline-offset-4 hover:text-fg" href={`/signup?next=${encodeURIComponent(next)}`}>Đăng ký</Link></> : <>Đã có tài khoản? <Link className="underline underline-offset-4 hover:text-fg" href={`/login?next=${encodeURIComponent(next)}`}>Đăng nhập</Link></>}
      </p>
    </div>
  );
}
