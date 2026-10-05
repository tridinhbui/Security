import { beforeEach, describe, expect, it } from "vitest";
import { createTestD1 } from "@/lib/db/__tests__/test-d1";
import { ScanRefusedError } from "@/lib/scanner/report";
import type { TlsInspection } from "@/lib/scanner/tls-inspect";
import type { Resolver } from "@/lib/ssrf/dns";
import { createHybridScanner } from "../hybrid-scanner";

const resolver: Resolver = async () => [{ address: "93.184.216.34", family: 4 }];
const PAGE = `<!doctype html><html lang="vi"><head><meta charset="utf-8"><title>Trang</title><script src="/app.js"></script></head><body><a href="/x">x</a></body></html>`;
const SEC = { "content-type": "text/html; charset=utf-8", "strict-transport-security": "max-age=31536000; includeSubDomains", "x-content-type-options": "nosniff" };

const GOOD_TLS: TlsInspection = {
  ok: true, resolved: ["93.184.216.34"],
  tls: { protocol: "TLSv1.3", cipher: "TLS_AES_256_GCM_SHA384", authorized: true, daysRemaining: 60, validityDays: 90, issuer: "Let's Encrypt", subject: "site.com", altNames: ["site.com"], keyType: "ec", keyBits: 256, curve: "prime256v1", chainLength: 2 },
  legacyTls: { tls10: false, tls11: false, h2: true },
};

function setup(opts: { httpsFails?: boolean; tls?: unknown; denyHosts?: string[] } = {}) {
  const db = createTestD1();
  const fetched: string[] = [];
  const containerCalls: string[] = [];
  const fetchImpl = (async (input: RequestInfo | URL) => {
    const url = String(input);
    if (url.startsWith("https://cloudflare-dns.com/")) return new Response(JSON.stringify({ Status: 0, Answer: [] }));
    fetched.push(url);
    if (url === "http://site.com/") return new Response(null, { status: 301, headers: { location: "https://site.com/" } });
    if (opts.httpsFails && url.startsWith("https://site.com")) throw new TypeError("tls handshake failed");
    if (url === "https://site.com/") return new Response(PAGE, { headers: SEC });
    if (url === "https://site.com/app.js") return new Response("console.log(1)", { headers: { "content-type": "application/javascript" } });
    return new Response("nope", { status: 404 });
  }) as typeof fetch;
  const container = async (req: Request) => {
    const path = new URL(req.url).pathname;
    containerCalls.push(path);
    if (path === "/tls") return new Response(JSON.stringify(opts.tls ?? GOOD_TLS));
    if (path === "/scan") return new Response(JSON.stringify({ t: "refused", code: "unreachable", message: "x" }) + "\n");
    return new Response(null, { status: 404 });
  };
  const scanner = createHybridScanner({ db, resolver, container, fetchImpl, denyHosts: opts.denyHosts });
  return { scanner, db, fetched, containerCalls, stages: [] as string[] };
}

describe("hybrid scanner", () => {
  let t: ReturnType<typeof setup>;
  beforeEach(() => { t = setup(); });

  it("Worker làm phần HTTP; container chỉ được gọi cho /tls", async () => {
    const report = await t.scanner.scan("https://site.com/", async (s) => void t.stages.push(s));
    expect(t.containerCalls).toEqual(["/tls"]);
    expect(report.findings.length).toBeGreaterThan(20);
    const byRule = (id: string) => report.findings.filter((f) => f.ruleId === id);
    expect(byRule("tls.certificate-expiry")[0]!.status).toBe("pass");
    expect(byRule("tls.protocol-version")[0]!.status).toBe("pass");
    expect(byRule("tls.hsts")[0]!.status).toBe("pass");
    expect(byRule("config.dns-email-security").length).toBeGreaterThan(0); // DNS đi qua DoH, không cần node:dns
    expect(t.stages).toContain("generating_report");
    expect(t.fetched).toContain("https://site.com/app.js"); // quét đầy đủ có tải script
    expect(report.stats.quick).toBeUndefined();
  });

  it("lần quét thứ hai dùng đệm TLS: container không bị đánh thức", async () => {
    await t.scanner.scan("https://site.com/", async () => undefined);
    t.containerCalls.length = 0;
    await t.scanner.scan("https://site.com/", async () => undefined);
    expect(t.containerCalls).toEqual([]);
  });

  it("chứng chỉ sắp hết hạn thì không dùng đệm (hỏi lại container)", async () => {
    const soon = { ...GOOD_TLS, tls: { ...GOOD_TLS.tls, daysRemaining: 5 } };
    t = setup({ tls: soon });
    await t.scanner.scan("https://site.com/", async () => undefined);
    await t.scanner.scan("https://site.com/", async () => undefined);
    expect(t.containerCalls).toEqual(["/tls", "/tls"]);
  });

  it("quét nhanh: không tải script ngoài, đánh dấu trong báo cáo", async () => {
    const report = await t.scanner.scan("https://site.com/", async () => undefined, { quick: true });
    expect(t.fetched).not.toContain("https://site.com/app.js");
    expect(report.stats.quick).toBe(true);
  });

  it("HTTPS lỗi trong Worker (chứng chỉ hỏng…) → chuyển sang bộ quét đầy đủ của container", async () => {
    t = setup({ httpsFails: true });
    await expect(t.scanner.scan("https://site.com/", async () => undefined)).rejects.toBeInstanceOf(ScanRefusedError);
    expect(t.containerCalls).toEqual(["/scan"]);
  });

  it("mục tiêu nội bộ bị từ chối ngay, không gọi gì", async () => {
    for (const u of ["http://127.0.0.1/", "http://169.254.169.254/", "https://localhost/", "http://10.0.0.1:8080/"]) {
      await expect(t.scanner.scan(u, async () => undefined)).rejects.toMatchObject({ name: "ScanRefusedError" });
    }
    expect(t.fetched).toEqual([]);
    expect(t.containerCalls).toEqual([]);
  });

  it("không tự quét chính hệ thống", async () => {
    t = setup({ denyHosts: ["site.com"] });
    await expect(t.scanner.scan("https://site.com/", async () => undefined)).rejects.toBeInstanceOf(ScanRefusedError);
    expect(t.fetched).toEqual([]);
  });

  it("container báo từ chối (SSRF) → ScanRefusedError", async () => {
    t = setup({ tls: { ok: false, refused: { code: "non_public_ip", message: "no" } } });
    await expect(t.scanner.scan("https://site.com/", async () => undefined)).rejects.toMatchObject({ code: "non_public_ip" });
  });
});
