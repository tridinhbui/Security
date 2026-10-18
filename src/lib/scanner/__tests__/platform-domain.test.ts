import { describe, expect, it } from "vitest";
import { runQuickScan } from "../quick";
import type { Resolver } from "@/lib/ssrf/dns";

const resolver: Resolver = async () => [{ address: "76.76.21.21", family: 4 }];
const HTML = `<!doctype html><html><head><meta charset="utf-8"><title>x</title></head><body>hi</body></html>`;

describe("quét website trên tên miền con của nền tảng (vd. *.vercel.app)", () => {
  it("không tra SPF/DMARC/CAA của tên miền nền tảng và báo mục DNS là ‘tham khảo’, không trừ điểm", async () => {
    const doh: string[] = [];
    const fetchImpl = (async (input: RequestInfo | URL) => {
      const url = String(input);
      if (url.startsWith("https://cloudflare-dns.com/")) { doh.push(url); return new Response(JSON.stringify({ Status: 0, Answer: [] })); }
      if (url === "http://myapp.vercel.app/") return new Response(null, { status: 308, headers: { location: "https://myapp.vercel.app/" } });
      if (url === "https://myapp.vercel.app/") return new Response(HTML, { headers: { "content-type": "text/html; charset=utf-8", "strict-transport-security": "max-age=63072000" } });
      return new Response("nope", { status: 404 });
    }) as typeof fetch;
    const r = await runQuickScan("myapp.vercel.app", { resolver, fetchImpl });
    expect(doh.filter((u) => /name=(_dmarc\.)?vercel\.app\b/.test(u))).toEqual([]);
    const dns = r.items.filter((i) => i.group === "dns");
    expect(dns).toHaveLength(1);
    expect(dns[0]).toMatchObject({ status: "info" });
    expect(dns[0]!.tech?.penalty ?? 0).toBe(0);
    expect(r.items.some((i) => /CAA|DNSSEC|DMARC|SPF/.test(i.text) && (i.status === "fail" || i.status === "warning"))).toBe(false);
  });
});
