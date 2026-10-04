import Link from "next/link";
import { ScanForm } from "@/components/ScanForm";
import { demoBeforeReport } from "@/lib/demo";
import { gradeColor, scoreColor, SEV_COLOR, SEV_LABEL } from "@/lib/format";
import { CATEGORIES } from "@/lib/scanner/types";
import { getUser } from "@/lib/auth/next";

const CHECKS: Record<(typeof CATEGORIES)[number], string> = {
  "Transport Security": "HTTPS availability, TLS versions and certificate, HTTP→HTTPS redirect, HSTS, password forms.",
  Headers: "Content-Security-Policy, clickjacking protection, X-Content-Type-Options, malformed or contradictory headers.",
  "Browser Security": "Mixed content, third-party scripts without integrity checks, CORS configuration.",
  "Cookies & Sessions": "Secure, HttpOnly and SameSite flags on cookies visible in responses; caching of login pages.",
  Exposure: "Source maps, secrets and keys in public JavaScript, client-side env values, robots.txt, sitemap.xml, security.txt.",
  Configuration: "Server/framework version headers, suspicious redirects, SPF/DMARC/CAA, technology fingerprint.",
  Privacy: "Referrer-Policy, Permissions-Policy, third-party requests that see your visitors.",
};

export default async function Home() {
  const user = await getUser();
  const demo = demoBeforeReport();
  const risks = demo.findings.filter((f) => f.status === "fail" && f.severity !== "info").slice(0, 3);

  return (
    <>
      <section className="mx-auto max-w-5xl px-5 pt-16 sm:pt-24 pb-16">
        <p className="text-sm text-muted mb-4">External website security audit</p>
        <h1 className="text-4xl sm:text-6xl font-semibold tracking-tight leading-[1.05] max-w-3xl">
          See what your website gives away — in plain English.
        </h1>
        <p className="mt-6 text-lg text-muted max-w-2xl">
          Paste a URL. VibeSec runs passive checks, scores your setup out of 100, and shows the exact fix for every problem. No security background needed.
        </p>
        <div className="mt-10 max-w-3xl"><ScanForm authed={!!user} /></div>
        <p className="mt-4 text-sm text-muted max-w-3xl">
          Non-destructive: a handful of ordinary page requests, no exploits, no password guessing, no crawling. {user ? "" : "Free account required so the scanner can’t be abused."}
        </p>
      </section>

      <section className="border-t border-line" aria-labelledby="example">
        <div className="mx-auto max-w-5xl px-5 py-16 grid gap-10 lg:grid-cols-[1fr_1.1fr] lg:gap-16 items-start">
          <div>
            <h2 id="example" className="text-2xl font-semibold tracking-tight">A report you can act on</h2>
            <p className="mt-3 text-muted">Every finding explains what we saw, why it matters, the evidence, and a copy-paste fix for your stack — or generic guidance when we can&apos;t tell what you run. We never invent configuration.</p>
            <Link href="/demo" className="inline-block mt-6 text-sm underline underline-offset-4 hover:text-fg text-muted">Explore the full demo report →</Link>
          </div>
          <div className="border border-line rounded-lg p-5 sm:p-6 bg-surface" aria-label="Example report preview">
            <div className="flex items-end justify-between gap-4">
              <div>
                <p className="text-xs text-muted">{demo.host}</p>
                <p className={`num text-6xl font-semibold tracking-tighter leading-none mt-1 ${scoreColor(demo.score)}`}>{demo.score}</p>
              </div>
              <p className={`text-4xl font-semibold ${gradeColor(demo.grade)}`}>{demo.grade}</p>
            </div>
            <ul className="mt-6 divide-y divide-line text-sm">
              {risks.map((f) => (
                <li key={f.fingerprint} className="py-2.5 flex gap-3">
                  <span className={`w-14 shrink-0 text-xs font-semibold uppercase mt-0.5 ${SEV_COLOR[f.severity]}`}>{SEV_LABEL[f.severity]}</span>
                  <span>{f.title}</span>
                </li>
              ))}
            </ul>
            <div className="mt-5 grid grid-cols-2 gap-x-6 gap-y-2 text-xs text-muted">
              {CATEGORIES.slice(0, 4).map((c) => (
                <div key={c} className="flex justify-between"><span>{c}</span><span className={`num ${scoreColor(demo.categoryScores[c] ?? null)}`}>{demo.categoryScores[c] ?? "n/a"}</span></div>
              ))}
            </div>
          </div>
        </div>
      </section>

      <section id="checks" className="border-t border-line" aria-labelledby="checks-h">
        <div className="mx-auto max-w-5xl px-5 py-16">
          <h2 id="checks-h" className="text-2xl font-semibold tracking-tight">What we check</h2>
          <dl className="mt-8 grid gap-x-16 gap-y-6 md:grid-cols-2">
            {CATEGORIES.map((c) => (
              <div key={c}><dt className="font-medium">{c}</dt><dd className="text-muted text-[15px] mt-1">{CHECKS[c]}</dd></div>
            ))}
          </dl>
        </div>
      </section>

      <section className="border-t border-line" aria-labelledby="safe-h">
        <div className="mx-auto max-w-5xl px-5 py-16 grid gap-10 md:grid-cols-2">
          <div>
            <h2 id="safe-h" className="text-2xl font-semibold tracking-tight">Safe by design</h2>
            <p className="mt-3 text-muted">VibeSec only looks at what any visitor&apos;s browser can already see. It is deterministic — no AI guessing — and never touches anything it shouldn&apos;t.</p>
          </div>
          <ul className="space-y-2.5 text-[15px] text-muted">
            {[
              "No password guessing, exploit payloads, SQL/XSS/command injection or fuzzing.",
              "Only public websites on ports 80/443; private networks and cloud metadata are blocked.",
              "A small, fixed number of requests to your homepage and a few same-origin files.",
              "Identifies itself as VibeSecBot; no full page bodies are stored and secrets are redacted.",
              "Rate limits and per-site cooldowns so it can’t be used to overload a website.",
            ].map((t) => <li key={t} className="flex gap-3"><span className="text-ok mt-0.5" aria-hidden>✓</span>{t}</li>)}
          </ul>
        </div>
      </section>
    </>
  );
}
