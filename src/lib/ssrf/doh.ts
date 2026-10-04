import type { ResolvedAddress, Resolver } from "./dns";

/**
 * DNS-over-HTTPS resolver for the Worker's early preflight (rejects obviously private/non-existent
 * names before queueing). The AUTHORITATIVE check still happens inside the scanner container, which
 * resolves and pins addresses itself — this one is only a fast fail.
 */
export function createDohResolver(fetchImpl: typeof fetch = fetch): Resolver {
  const query = async (name: string, type: "A" | "AAAA"): Promise<ResolvedAddress[]> => {
    const res = await fetchImpl(`https://cloudflare-dns.com/dns-query?name=${encodeURIComponent(name)}&type=${type}`, {
      headers: { accept: "application/dns-json" },
      signal: AbortSignal.timeout(4000),
    });
    if (!res.ok) throw Object.assign(new Error("doh_http"), { code: "EDOH" });
    const body = (await res.json()) as { Status: number; Answer?: { type: number; data: string }[] };
    if (body.Status === 3) throw Object.assign(new Error("nxdomain"), { code: "ENOTFOUND" });
    if (body.Status !== 0) throw Object.assign(new Error("doh_status"), { code: "EDOH" });
    const want = type === "A" ? 1 : 28;
    return (body.Answer ?? []).filter((a) => a.type === want).map((a) => ({ address: a.data, family: type === "A" ? 4 : 6 }));
  };
  return async (host) => {
    const [a, aaaa] = await Promise.all([query(host, "A"), query(host, "AAAA").catch(() => [])]);
    return [...a, ...aaaa];
  };
}
