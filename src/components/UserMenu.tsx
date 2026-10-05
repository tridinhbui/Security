"use client";
import Link from "next/link";
import { useRouter } from "next/navigation";
import { useEffect, useId, useRef, useState } from "react";

function initials(name: string | null, email: string): string {
  const src = (name?.trim() || email.split("@")[0] || "?").split(/[\s._-]+/).filter(Boolean);
  return ((src[0]?.[0] ?? "?") + (src.length > 1 ? src[src.length - 1]![0]! : "")).toUpperCase();
}

export function Avatar({ name, email, url, size = 32 }: { name: string | null; email: string; url: string | null; size?: number }) {
  const [broken, setBroken] = useState(false);
  const style = { width: size, height: size };
  if (url && !broken) {
    // eslint-disable-next-line @next/next/no-img-element
    return <img src={url} alt="" referrerPolicy="no-referrer" onError={() => setBroken(true)} style={style} className="rounded-full border border-line object-cover" />;
  }
  return <span aria-hidden style={style} className="grid place-items-center rounded-full bg-accent-soft font-mono text-[11px] font-semibold text-accent">{initials(name, email)}</span>;
}

/** Menu hồ sơ: đóng bằng Esc / bấm ra ngoài, trả focus về nút, đăng xuất gọi API thật rồi làm mới phiên. */
export function UserMenu({ name, email, avatarUrl }: { name: string | null; email: string; avatarUrl: string | null }) {
  const router = useRouter();
  const [open, setOpen] = useState(false);
  const [busy, setBusy] = useState(false);
  const root = useRef<HTMLDivElement>(null);
  const btn = useRef<HTMLButtonElement>(null);
  const menuId = useId();

  useEffect(() => {
    if (!open) return;
    const onDoc = (e: MouseEvent) => { if (!root.current?.contains(e.target as Node)) setOpen(false); };
    const onKey = (e: KeyboardEvent) => { if (e.key === "Escape") { setOpen(false); btn.current?.focus(); } };
    document.addEventListener("mousedown", onDoc);
    document.addEventListener("keydown", onKey);
    return () => { document.removeEventListener("mousedown", onDoc); document.removeEventListener("keydown", onKey); };
  }, [open]);

  async function signOut() {
    setBusy(true);
    try { await fetch("/api/auth/logout", { method: "POST" }); } finally {
      setOpen(false);
      router.push("/");
      router.refresh();
    }
  }

  const item = "block w-full rounded-lg px-3 py-2 text-left text-sm text-fg transition-colors hover:bg-surface focus-visible:bg-surface";
  return (
    <div ref={root} className="relative">
      <button ref={btn} type="button" aria-haspopup="menu" aria-expanded={open} aria-controls={menuId} onClick={() => setOpen((v) => !v)}
        className="flex items-center gap-2 rounded-full border border-line-strong bg-white p-0.5 pr-2.5 shadow-crisp transition-colors hover:border-fg/40">
        <Avatar name={name} email={email} url={avatarUrl} />
        <span className="hidden max-w-[10rem] truncate text-[13px] font-medium sm:block">{name ?? email}</span>
        <svg viewBox="0 0 24 24" className={`size-3.5 text-faint transition-transform duration-200 ${open ? "rotate-180" : ""}`} fill="none" stroke="currentColor" strokeWidth="2.2" strokeLinecap="round"><path d="m6 9 6 6 6-6" /></svg>
      </button>
      {open && (
        <div id={menuId} role="menu" aria-label="Menu tài khoản" className="pop absolute right-0 mt-2 w-64 origin-top-right rounded-xl border border-line bg-white p-1.5 shadow-pop">
          <div className="flex items-center gap-3 border-b border-line px-3 pb-3 pt-2">
            <Avatar name={name} email={email} url={avatarUrl} size={36} />
            <div className="min-w-0">
              {name && <p className="truncate text-sm font-medium">{name}</p>}
              <p className="truncate text-xs text-muted">{email}</p>
            </div>
          </div>
          <div className="pt-1.5">
            <Link role="menuitem" href="/dashboard" className={item} onClick={() => setOpen(false)}>Bảng điều khiển</Link>
            <Link role="menuitem" href="/scans" className={item} onClick={() => setOpen(false)}>Lịch sử quét</Link>
            <Link role="menuitem" href="/settings" className={item} onClick={() => setOpen(false)}>Cài đặt</Link>
            <button role="menuitem" type="button" onClick={signOut} disabled={busy} className={`${item} text-crit disabled:opacity-60`}>{busy ? "Đang đăng xuất…" : "Đăng xuất"}</button>
          </div>
        </div>
      )}
    </div>
  );
}
