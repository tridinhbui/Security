"use client";

import Link from "next/link";
import { usePathname } from "next/navigation";

export interface NavItem { href: string; label: string; accent?: boolean }

export function NavLinks({ items }: { items: NavItem[] }) {
  const path = usePathname();
  return (
    <>
      {items.map((l) => {
        const active = l.href === "/" ? path === "/" : path === l.href || path.startsWith(`${l.href}/`);
        return (
          <Link
            key={l.href} href={l.href} aria-current={active ? "page" : undefined}
            className={`relative px-3.5 py-5 text-[13.5px] transition-colors ${active ? "font-medium text-fg" : l.accent ? "font-medium text-accent" : "text-muted hover:text-fg"}`}
          >
            {l.label}
            {active && <span aria-hidden className="absolute inset-x-3.5 bottom-0 h-0.5 rounded-full bg-accent" />}
            {active && <span aria-hidden className="absolute left-1/2 top-[calc(100%-12px)] size-1 -translate-x-1/2 rounded-full bg-accent" />}
          </Link>
        );
      })}
    </>
  );
}
