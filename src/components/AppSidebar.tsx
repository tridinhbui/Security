"use client";

import Link from "next/link";
import { usePathname, useRouter } from "next/navigation";
import { useEffect, useRef, useState } from "react";
import { Logo } from "./Logo";
import { ModeToggle } from "./matmat/ModeToggle";
import { Avatar } from "./UserMenu";

interface Item { href: string; label: string; icon: string; badge?: number; exact?: boolean }
interface Props { name: string | null; email: string; avatarUrl: string | null; isAdmin: boolean; supportUnread: number; adminUnread: number }

const ICONS: Record<string, string> = {
  dashboard: "M4 13h6V4H4v9Zm0 7h6v-5H4v5Zm10 0h6v-9h-6v9Zm0-16v5h6V4h-6Z",
  history: "M12 8v5l3 2M3 12a9 9 0 1 0 3-6.7M3 4v5h5",
  support: "M4 5h16v11H9l-5 4V5Z",
  settings: "M12 15a3 3 0 1 0 0-6 3 3 0 0 0 0 6Zm7.4-3a7.4 7.4 0 0 0-.1-1.2l2-1.6-2-3.4-2.4 1a7.6 7.6 0 0 0-2-1.2L14.5 3h-4l-.4 2.6a7.6 7.6 0 0 0-2 1.2l-2.4-1-2 3.4 2 1.6a7.4 7.4 0 0 0 0 2.4l-2 1.6 2 3.4 2.4-1a7.6 7.6 0 0 0 2 1.2l.4 2.6h4l.4-2.6a7.6 7.6 0 0 0 2-1.2l2.4 1 2-3.4-2-1.6c.1-.4.1-.8.1-1.2Z",
  admin: "M12 3 4.5 6v5.5c0 4.4 3 7.9 7.5 9.5 4.5-1.6 7.5-5.1 7.5-9.5V6L12 3Zm-2.5 9 2 2 3.5-4",
  book: "M5 4h10a3 3 0 0 1 3 3v13H8a3 3 0 0 1-3-3V4Zm0 13a3 3 0 0 1 3-3h10",
  play: "M8 5v14l11-7L8 5Z",
};

function Icon({ name }: { name: string }) {
  return <svg viewBox="0 0 24 24" className="size-[18px] shrink-0" fill="none" stroke="currentColor" strokeWidth="1.8" strokeLinecap="round" strokeLinejoin="round" aria-hidden><path d={ICONS[name]} /></svg>;
}

/**
 * Thanh điều hướng dọc sau khi đăng nhập. Máy tính: cố định bên trái. Điện thoại: thanh trên + ngăn kéo (Esc / bấm ra ngoài để đóng,
 * tự đóng khi chuyển trang). Mục đang xem được đánh dấu bằng aria-current.
 */
export function AppSidebar({ name, email, avatarUrl, isAdmin, supportUnread, adminUnread }: Props) {
  const pathname = usePathname();
  const router = useRouter();
  const [open, setOpen] = useState(false);
  const [busy, setBusy] = useState(false);
  const toggle = useRef<HTMLButtonElement>(null);

  useEffect(() => setOpen(false), [pathname]);
  useEffect(() => {
    if (!open) return;
    const onKey = (e: KeyboardEvent) => { if (e.key === "Escape") { setOpen(false); toggle.current?.focus(); } };
    document.addEventListener("keydown", onKey);
    document.body.style.overflow = "hidden";
    return () => { document.removeEventListener("keydown", onKey); document.body.style.overflow = ""; };
  }, [open]);

  const main: Item[] = [
    { href: "/dashboard", label: "Bảng điều khiển", icon: "dashboard", exact: true },
    { href: "/scans", label: "Lịch sử quét", icon: "history" },
    { href: "/ho-tro", label: "Hỗ trợ trực tiếp", icon: "support", badge: supportUnread },
    { href: "/settings", label: "Cài đặt", icon: "settings" },
  ];
  const admin: Item[] = isAdmin ? [{ href: "/admin", label: "Quản trị", icon: "admin", badge: adminUnread }] : [];
  const more: Item[] = [
    { href: "/phuong-phap", label: "Phương pháp", icon: "book" },
    { href: "/demo", label: "Bản demo", icon: "play" },
  ];

  const active = (i: Item) => (i.exact ? pathname === i.href : pathname === i.href || pathname.startsWith(`${i.href}/`));
  const link = (i: Item) => {
    const on = active(i);
    return (
      <li key={i.href}>
        <Link href={i.href} aria-current={on ? "page" : undefined}
          className={`group flex items-center gap-3 rounded-lg px-3 py-2 text-sm transition-colors ${on ? "bg-accent-soft font-medium text-accent" : "text-muted hover:bg-surface hover:text-fg"}`}>
          <Icon name={i.icon} />
          <span className="flex-1 truncate">{i.label}</span>
          {!!i.badge && <span className="num grid min-w-5 place-items-center rounded-full bg-accent px-1.5 text-[11px] font-semibold leading-5 text-white" aria-label={`${i.badge} mới`}>{i.badge > 9 ? "9+" : i.badge}</span>}
        </Link>
      </li>
    );
  };

  async function signOut() {
    setBusy(true);
    try { await fetch("/api/auth/logout", { method: "POST" }); } finally { router.push("/"); router.refresh(); }
  }

  const nav = (
    <div className="flex h-full flex-col">
      <div className="flex items-center justify-between gap-2 px-4 pb-3 pt-5">
        <Logo href="/dashboard" />
        <button type="button" onClick={signOut} disabled={busy} title="Đăng xuất" aria-label="Đăng xuất" className="grid size-8 shrink-0 place-items-center rounded-lg text-muted transition-colors hover:bg-crit/5 hover:text-crit disabled:opacity-60">
          <svg viewBox="0 0 24 24" className="size-[18px]" fill="none" stroke="currentColor" strokeWidth="1.8" strokeLinecap="round" strokeLinejoin="round" aria-hidden><path d="M9 4H5v16h4M16 8l4 4-4 4M20 12H9" /></svg>
        </button>
      </div>
      <div className="px-3">
        <Link href="/dashboard#quet" className="btn-primary w-full justify-start gap-2.5 !px-3">
          <svg viewBox="0 0 24 24" className="size-4" fill="none" stroke="currentColor" strokeWidth="2.2" strokeLinecap="round" aria-hidden><path d="M12 5v14M5 12h14" /></svg>Quét website mới
        </Link>
      </div>
      <nav aria-label="Điều hướng chính" className="mt-5 flex-1 overflow-y-auto px-3">
        <p className="eyebrow px-3 pb-1.5">Khu vực làm việc</p>
        <ul className="space-y-0.5">{main.map(link)}</ul>
        {admin.length > 0 && <><p className="eyebrow px-3 pb-1.5 pt-5">Quản trị</p><ul className="space-y-0.5">{admin.map(link)}</ul></>}
        <p className="eyebrow px-3 pb-1.5 pt-5">Tài nguyên</p>
        <ul className="space-y-0.5">{more.map(link)}</ul>
      </nav>
      <div className="border-t border-line p-3">
        <div className="px-1 pb-2"><p className="eyebrow pb-1.5 pl-2">Chế độ hiển thị</p><ModeToggle className="flex w-full [&>button]:flex-1" /></div>
        <div className="flex items-center gap-3 rounded-lg px-2 py-1.5">
          <Avatar name={name} email={email} url={avatarUrl} size={36} />
          <div className="min-w-0 flex-1">
            {name && <p className="truncate text-sm font-medium">{name}</p>}
            <p className="truncate text-xs text-muted">{email}</p>
          </div>
        </div>
        <button type="button" onClick={signOut} disabled={busy} className="mt-1 flex w-full items-center gap-3 rounded-lg px-3 py-2 text-sm text-crit transition-colors hover:bg-crit/5 disabled:opacity-60">
          <svg viewBox="0 0 24 24" className="size-[18px]" fill="none" stroke="currentColor" strokeWidth="1.8" strokeLinecap="round" strokeLinejoin="round" aria-hidden><path d="M9 4H5v16h4M16 8l4 4-4 4M20 12H9" /></svg>
          {busy ? "Đang đăng xuất…" : "Đăng xuất"}
        </button>
      </div>
    </div>
  );

  return (
    <>
      {/* Máy tính */}
      <aside className="fixed inset-y-0 left-0 z-30 hidden w-64 border-r border-line bg-white lg:block">{nav}</aside>

      {/* Điện thoại / máy tính bảng: thanh trên + ngăn kéo */}
      <div className="sticky top-0 z-30 flex h-14 items-center justify-between border-b border-line bg-white/90 px-4 backdrop-blur lg:hidden">
        <Logo href="/dashboard" />
        <button ref={toggle} type="button" aria-label="Mở menu điều hướng" aria-expanded={open} aria-controls="app-drawer" onClick={() => setOpen(true)}
          className="grid size-9 place-items-center rounded-md border border-line-strong bg-white">
          <svg viewBox="0 0 24 24" className="size-4" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" aria-hidden><path d="M4 7h16M4 12h16M4 17h16" /></svg>
        </button>
      </div>
      {open && (
        <div className="fixed inset-0 z-40 lg:hidden">
          <button type="button" aria-label="Đóng menu" className="fade-in absolute inset-0 bg-fg/35" onClick={() => setOpen(false)} />
          <aside id="app-drawer" role="dialog" aria-modal="true" aria-label="Menu điều hướng" className="pop absolute inset-y-0 left-0 w-72 max-w-[85vw] border-r border-line bg-white shadow-pop">{nav}</aside>
        </div>
      )}
    </>
  );
}
