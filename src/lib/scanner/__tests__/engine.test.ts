import http from "node:http";
import type { AddressInfo } from "node:net";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { runScan, ScanRefusedError } from "../engine";
import type { Resolver } from "@/lib/ssrf/dns";

const SECRET = "sk_live_" + "Z9y8X7w6V5u4T3s2R1q0P9o8";
let server: http.Server;
let port: number;
let hits: string[] = [];

beforeAll(async () => {
  server = http.createServer((req, res) => {
    const url = req.url ?? "/";
    hits.push(`${req.method} ${url}`);
    if (url === "/") {
      res.writeHead(200, { "content-type": "text/html", server: "nginx/1.18.0", "set-cookie": "session=abc123; Path=/", "access-control-allow-origin": String(req.headers.origin ?? ""), "access-control-allow-credentials": "true" });
      return void res.end(`<html><head><title>T</title><script src="/app.js"></script></head><body><a href="/login">Login</a><img src="http://example.org/x.png"></body></html>`);
    }
    if (url === "/app.js") {
      res.writeHead(200, { "content-type": "application/javascript" });
      return void res.end(`var k="${SECRET}";\n//# sourceMappingURL=app.js.map`);
    }
    if (url === "/app.js.map") {
      res.writeHead(200, { "content-type": "application/json" });
      return void res.end(`{"version":3,"sources":["a.ts"],"mappings":"AAAA"}`);
    }
    if (url === "/robots.txt") {
      res.writeHead(200, { "content-type": "text/plain" });
      return void res.end("User-agent: *\nDisallow: /admin\n");
    }
    if (url === "/sitemap.xml") {
      // SPA-style catch-all: 200 + HTML must NOT count as a real file
      res.writeHead(200, { "content-type": "text/html" });
      return void res.end("<html>app shell</html>");
    }
    if (url === "/login") {
      res.writeHead(200, { "content-type": "text/html" });
      return void res.end(`<form method="post" action="/login"><input type="password"></form>`);
    }
    res.writeHead(404, { "content-type": "text/html" });
    res.end("not found");
  });
  await new Promise<void>((r) => server.listen(0, "127.0.0.1", r));
  port = (server.address() as AddressInfo).port;
});
afterAll(() => server.close());

const resolver: Resolver = async () => { throw Object.assign(new Error("nx"), { code: "ENOTFOUND" }); };
const stubDns = async () => ({ domain: "example.org", caa: [], spf: null, dmarc: null });

describe("runScan (end-to-end against a local site)", () => {
  it("produces a complete, redacted, deterministic report", async () => {
    hits = [];
    const stages: string[] = [];
    const report = await runScan("http://site.example.org/", {
      testRoutes: { "site.example.org": { port } }, resolver,
      onStage: (s) => void stages.push(s),
      collectOverrides: { lookupDns: stubDns },
    });

    expect(stages[0]).toBe("validating");
    expect(stages).toContain("scanning_transport");
    expect(stages).toContain("checking_headers");
    expect(stages).toContain("analyzing_client");
    expect(stages.at(-1)).toBe("generating_report");

    const byRule = (id: string) => report.findings.filter((x) => x.ruleId === id);
    // HTTPS isn't served by this fixture
    expect(byRule("tls.https-available")[0]).toMatchObject({ status: "fail", severity: "high" });
    // Secret in public JS → Critical, with no raw value anywhere in the report
    expect(byRule("exposure.secrets")[0]).toMatchObject({ status: "fail", severity: "critical" });
    expect(JSON.stringify(report)).not.toContain(SECRET);
    expect(JSON.stringify(report)).not.toContain("abc123"); // cookie value
    // Source map exposed
    expect(byRule("exposure.source-maps")[0]).toMatchObject({ status: "fail", severity: "medium" });
    // CORS reflection with credentials
    expect(byRule("browser.cors")[0]).toMatchObject({ status: "fail", severity: "high" });
    // version disclosure
    expect(byRule("config.server-disclosure")[0]).toMatchObject({ status: "fail", severity: "low" });
    // SPA fallback is not a sitemap
    expect(byRule("exposure.sitemap-xml")[0]!.status).toBe("info");
    // Login page discovered → cache check ran
    expect(byRule("cookies.cache-control-sensitive").length).toBeGreaterThan(0);
    // Critical finding caps the score
    expect(report.score.score).toBeLessThanOrEqual(59);
    expect(report.score.grade).toBe("F");
    expect(report.topRisks[0]!.severity).toBe("critical");
    expect(report.disclaimer).toMatch(/not proof/);
    expect(report.stats.ruleErrors).toEqual([]);
    expect(report.stats.requests).toBeLessThanOrEqual(28);
    expect(report.targets.find((t) => t.role === "http_home")!.headers["set-cookie"]).toEqual(["session=<redacted>; Path=/"]);
  });

  it("only requests a small, fixed set of same-origin URLs (no crawling)", async () => {
    const allowed = new Set(["GET /", "GET /app.js", "GET /app.js.map", "GET /robots.txt", "GET /sitemap.xml", "GET /.well-known/security.txt", "GET /security.txt", "GET /login"]);
    for (const h of hits) expect(allowed.has(h), h).toBe(true);
  });

  it("refuses private/internal targets before any request", async () => {
    for (const [u, code] of [["http://127.0.0.1/", "non_public_ip"], ["http://169.254.169.254/latest/meta-data", "non_public_ip"], ["localhost", "internal_hostname"], ["ftp://example.com", "scheme_not_allowed"], ["https://example.com:8443", "port_not_allowed"]] as const) {
      const err = await runScan(u, { resolver }).catch((e) => e);
      expect(err).toBeInstanceOf(ScanRefusedError);
      expect(err.code).toBe(code);
    }
  });

  it("refuses hostnames that resolve to private space (DNS rebinding / split-horizon)", async () => {
    const priv: Resolver = async () => [{ address: "10.1.2.3", family: 4 }];
    const err = await runScan("https://intranet.example.org", { resolver: priv, dnsCache: new Map() }).catch((e) => e);
    expect(err).toMatchObject({ code: "non_public_ip" });
    const mixed: Resolver = async () => [{ address: "93.184.216.34", family: 4 }, { address: "127.0.0.1", family: 4 }];
    expect(await runScan("https://mixed.example.org", { resolver: mixed, dnsCache: new Map() }).catch((e) => e)).toMatchObject({ code: "dns_mixed_answers" });
  });

  it("fails clearly (not with a fake 100/A) when the site is unreachable", async () => {
    const dead = http.createServer();
    await new Promise<void>((r) => dead.listen(0, "127.0.0.1", r));
    const p = (dead.address() as AddressInfo).port;
    await new Promise<void>((r) => dead.close(() => r()));
    const err = await runScan("http://down.example.org/", { testRoutes: { "down.example.org": { port: p } }, resolver, collectOverrides: { lookupDns: stubDns } }).catch((e) => e);
    expect(err).toBeInstanceOf(ScanRefusedError);
    expect(err.code).toBe("unreachable");
  });

  it("honours the per-scan request budget", async () => {
    const { ScanBudget } = await import("@/lib/ssrf/fetch");
    const report = await runScan("http://site.example.org/", {
      testRoutes: { "site.example.org": { port } }, resolver, budget: new ScanBudget(4), collectOverrides: { lookupDns: stubDns },
    });
    expect(report.stats.requests).toBeLessThanOrEqual(4);
    expect(report.stats.hitLimit).toBe("request_budget");
  });
});
