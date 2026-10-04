import Link from "next/link";
import { getUser } from "@/lib/auth/next";

export async function SiteHeader() {
  const email = (await getUser())?.email ?? null;
  return (
    <header className="border-b border-line">
      <div className="mx-auto max-w-5xl px-5 h-14 flex items-center justify-between gap-4">
        <Link href="/" className="font-semibold tracking-tight text-[15px] flex items-center gap-2">
          <span aria-hidden className="inline-block size-2 rounded-[2px] bg-fg" />
          VibeSec
        </Link>
        <nav className="flex items-center gap-1 text-sm text-muted">
          <Link href="/demo" className="px-3 py-1.5 hover:text-fg">Bản demo</Link>
          {email ? (
            <>
              <Link href="/dashboard" className="px-3 py-1.5 hover:text-fg">Bảng điều khiển</Link>
              <Link href="/settings" className="px-3 py-1.5 hover:text-fg hidden sm:block">Cài đặt</Link>
            </>
          ) : (
            <>
              <Link href="/login" className="px-3 py-1.5 hover:text-fg">Đăng nhập</Link>
              <Link href="/signup" className="ml-1 px-3 py-1.5 rounded-md bg-fg text-bg font-medium hover:bg-white">Đăng ký</Link>
            </>
          )}
        </nav>
      </div>
    </header>
  );
}
