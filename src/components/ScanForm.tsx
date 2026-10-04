"use client";

import { useRouter } from "next/navigation";
import { useEffect, useRef, useState } from "react";

const ERRORS: Record<string, string> = {
  invalid_url: "That doesn't look like a valid website address.",
  scheme_not_allowed: "Only http and https addresses can be scanned.",
  internal_hostname: "Internal or local hostnames can't be scanned. Enter a public website.",
  non_public_ip: "That address isn't publicly reachable, so it can't be scanned.",
  port_not_allowed: "Only the standard web ports (80 and 443) can be scanned.",
  credentials_not_allowed: "Remove the username/password from the URL.",
  dns_failed: "We couldn't find that domain. Check the spelling.",
};

interface Props {
  authed: boolean;
  initialUrl?: string;
  autoStart?: boolean;
  size?: "lg" | "md";
  label?: string;
}

export function ScanForm({ authed, initialUrl = "", autoStart = false, size = "lg", label = "Scan website" }: Props) {
  const router = useRouter();
  const [url, setUrl] = useState(initialUrl);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const started = useRef(false);

  async function submit(value: string) {
    if (!value.trim()) return setError("Enter a website address, like example.com");
    if (!authed) {
      router.push(`/login?next=${encodeURIComponent(`/dashboard?scan=${encodeURIComponent(value.trim())}`)}`);
      return;
    }
    setBusy(true);
    setError(null);
    try {
      const res = await fetch("/api/scans", { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify({ url: value.trim() }) });
      const body = await res.json().catch(() => ({}));
      if (res.status === 401) return router.push(`/login?next=/dashboard`);
      if (!res.ok) {
        setError(body.message ?? ERRORS[body.error] ?? "Something went wrong. Please try again.");
        setBusy(false);
        return;
      }
      router.push(`/scans/${body.id}`);
    } catch {
      setError("Network error. Please try again.");
      setBusy(false);
    }
  }

  useEffect(() => {
    if (autoStart && initialUrl && !started.current) {
      started.current = true;
      void submit(initialUrl);
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  const big = size === "lg";
  return (
    <form onSubmit={(e) => { e.preventDefault(); void submit(url); }} noValidate className="w-full">
      <div className={`flex flex-col sm:flex-row gap-2 ${big ? "" : ""}`}>
        <label className="sr-only" htmlFor="scan-url">Website URL</label>
        <input
          id="scan-url" name="url" type="text" inputMode="url" autoComplete="off" autoCapitalize="none" spellCheck={false}
          placeholder="example.com" value={url} onChange={(e) => setUrl(e.target.value)} disabled={busy}
          aria-invalid={!!error} aria-describedby={error ? "scan-error" : undefined}
          className={`flex-1 min-w-0 bg-surface border border-line-strong rounded-md px-4 text-fg placeholder:text-faint focus:border-fg/60 focus:outline-none ${big ? "h-14 text-lg" : "h-11 text-base"}`}
        />
        <button type="submit" disabled={busy}
          className={`rounded-md bg-fg text-bg font-medium hover:bg-white disabled:opacity-60 transition-colors ${big ? "h-14 px-7 text-base" : "h-11 px-5 text-sm"}`}>
          {busy ? "Starting…" : label}
        </button>
      </div>
      {error && <p id="scan-error" role="alert" className="mt-3 text-sm text-high">{error}</p>}
    </form>
  );
}
