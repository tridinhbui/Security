import type { Metadata, Viewport } from "next";
import Link from "next/link";
import "./globals.css";
import { SiteHeader } from "@/components/SiteHeader";

export const metadata: Metadata = {
  title: { default: "VibeSec — plain-English website security audits", template: "%s · VibeSec" },
  description: "Paste a URL and get a clear, beginner-friendly security audit. Passive, non-destructive checks with exact fixes.",
  robots: { index: true, follow: true },
};
export const viewport: Viewport = { themeColor: "#0a0b0d", width: "device-width", initialScale: 1 };

export default function RootLayout({ children }: { children: React.ReactNode }) {
  return (
    <html lang="en">
      <body className="min-h-dvh flex flex-col">
        <SiteHeader />
        <main className="flex-1">{children}</main>
        <footer className="border-t border-line mt-24">
          <div className="mx-auto max-w-5xl px-5 py-8 text-sm text-muted flex flex-col sm:flex-row gap-3 sm:items-center sm:justify-between">
            <p>VibeSec runs passive, non-destructive checks only. Scores are external configuration assessments, not proof a site is secure.</p>
            <nav className="flex gap-5 shrink-0">
              <Link className="hover:text-fg" href="/demo">Demo</Link>
              <Link className="hover:text-fg" href="/#checks">What we check</Link>
            </nav>
          </div>
        </footer>
      </body>
    </html>
  );
}
