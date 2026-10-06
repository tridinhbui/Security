import Link from "next/link";

export function Logo({ className = "", href = "/" }: { className?: string; href?: string }) {
  return (
    <Link href={href} className={`group flex items-center gap-3 ${className}`} aria-label="VibeSec — trang chủ">
      <span aria-hidden className="grid size-[26px] place-items-center rounded-lg bg-fg text-white shadow-crisp transition-transform duration-200 group-hover:-rotate-6">
        <svg viewBox="0 0 24 24" className="size-4" fill="none" stroke="currentColor" strokeWidth="2.2" strokeLinecap="round" strokeLinejoin="round"><path d="M12 3 4.5 6v5.5c0 4.4 3 7.9 7.5 9.5 4.5-1.6 7.5-5.1 7.5-9.5V6L12 3Z" /><path d="m9 12 2.2 2.2L15.5 10" /></svg>
      </span>
      <span className="mono text-[13px] font-medium uppercase tracking-[0.28em]">vibesec</span>
    </Link>
  );
}
