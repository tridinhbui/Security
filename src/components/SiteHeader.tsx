import Link from "next/link";
import { getAdmin } from "@/lib/auth/admin";
import { getUser } from "@/lib/auth/next";
import { NavLinks, type NavItem } from "./NavLinks";
import { UserMenu } from "./UserMenu";

export function Logo({ className = "" }: { className?: string }) {
  return (
    <Link href="/" className={`group flex items-center gap-3 ${className}`} aria-label="VibeSec — trang chủ">
      <span aria-hidden className="grid size-[26px] place-items-center rounded-lg bg-fg text-white shadow-crisp transition-transform duration-200 group-hover:-rotate-6">
        <svg viewBox="0 0 24 24" className="size-4" fill="none" stroke="currentColor" strokeWidth="2.2" strokeLinecap="round" strokeLinejoin="round"><path d="M12 3 4.5 6v5.5c0 4.4 3 7.9 7.5 9.5 4.5-1.6 7.5-5.1 7.5-9.5V6L12 3Z" /><path d="m9 12 2.2 2.2L15.5 10" /></svg>
      </span>
      <span className="mono text-[13px] font-medium uppercase tracking-[0.28em]">vibesec</span>
    </Link>
  );
}

export async function SiteHeader() {
  const user = await getUser();
  const isAdmin = user ? !!(await getAdmin()) : false;
  const links = [{ href: "/demo", label: "Bản demo" }, { href: "/phuong-phap", label: "Phương pháp" }];
  const nav: NavItem[] = [{ href: "/", label: "Scan" }, ...links, ...(user ? [{ href: "/dashboard", label: "Bảng điều khiển" }, { href: "/ho-tro", label: "Hỗ trợ" }] : []), ...(isAdmin ? [{ href: "/admin", label: "Quản trị", accent: true }] : [])];
  return (
    <header className="sticky top-0 z-40 border-b border-line bg-white/85 backdrop-blur-md">
      <div className="container-x flex h-[62px] items-center justify-between gap-4">
        <div className="flex items-center">
          <Logo />
          <nav aria-label="Điều hướng chính" className="ml-6 hidden items-center sm:flex"><NavLinks items={nav} /></nav>
        </div>
        <div className="flex items-center gap-2">
          {user ? (
            <UserMenu name={user.name} email={user.email} avatarUrl={user.avatar_url} />
          ) : (
            <>
              <Link href="/login" className="btn-ghost hidden !h-10 sm:inline-flex">Đăng nhập</Link>
              <Link href="/signup" className="btn-dark !h-10">Bắt đầu miễn phí<svg viewBox="0 0 24 24" className="size-4" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" aria-hidden><path d="M5 12h14M13 6l6 6-6 6" /></svg></Link>
            </>
          )}
          {/* Menu thu gọn cho điện thoại: <details> thuần HTML nên không phụ thuộc JS */}
          <details className="relative sm:hidden">
            <summary aria-label="Mở menu" className="grid size-8 cursor-pointer place-items-center rounded-md border border-line-strong bg-white"><svg viewBox="0 0 24 24" className="size-4" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round"><path d="M4 7h16M4 12h16M4 17h16" /></svg></summary>
            <div className="absolute right-0 mt-2 w-52 rounded-xl border border-line bg-white p-1.5 shadow-pop">
              {links.map((l) => <Link key={l.href} href={l.href} className="block rounded-lg px-3 py-2 text-sm hover:bg-surface">{l.label}</Link>)}
              {user ? <Link href="/dashboard" className="block rounded-lg px-3 py-2 text-sm hover:bg-surface">Bảng điều khiển</Link> : <Link href="/login" className="block rounded-lg px-3 py-2 text-sm hover:bg-surface">Đăng nhập</Link>}
              {user && <Link href="/ho-tro" className="block rounded-lg px-3 py-2 text-sm hover:bg-surface">Hỗ trợ</Link>}
              {isAdmin && <Link href="/admin" className="block rounded-lg px-3 py-2 text-sm font-medium text-accent hover:bg-accent-soft">Quản trị</Link>}
            </div>
          </details>
        </div>
      </div>
    </header>
  );
}
