import http from "node:http";
import type { AddressInfo } from "node:net";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import type { Resolver } from "../dns";
import { createSafeFetcher, ScanBudget } from "../fetch";

let server: http.Server;
let port: number;
const requests: string[] = [];

beforeAll(async () => {
  server = http.createServer((req, res) => {
    requests.push(req.url ?? "");
    const url = req.url ?? "/";
    if (url === "/ok") {
      res.writeHead(200, { "content-type": "text/html", "x-test": "1", "set-cookie": ["a=1", "b=2"] });
      return void res.end("<html>hello</html>");
    }
    if (url === "/big") {
      res.writeHead(200, { "content-type": "text/plain" });
      const chunk = Buffer.alloc(64 * 1024, 97);
      let sent = 0;
      const t = setInterval(() => {
        if (res.destroyed || sent > 50) return clearInterval(t);
        res.write(chunk);
        sent++;
      }, 1);
      return;
    }
    if (url === "/slow") {
      res.writeHead(200, { "content-type": "text/plain" });
      const t = setInterval(() => res.destroyed ? clearInterval(t) : res.write("x"), 50); // slow-drip
      return;
    }
    if (url === "/hang") return; // never responds
    if (url === "/to-ok") {
      res.writeHead(302, { location: "http://site.example.org/ok" });
      return void res.end();
    }
    if (url === "/loop") {
      res.writeHead(302, { location: "http://site.example.org/loop" });
      return void res.end();
    }
    if (url === "/chain") {
      res.writeHead(302, { location: "/chain2" });
      return void res.end();
    }
    if (url === "/chain2") {
      res.writeHead(301, { location: "/ok" });
      return void res.end();
    }
    if (url.startsWith("/endless")) {
      res.writeHead(302, { location: `/endless?${Math.random()}` });
      return void res.end();
    }
    const evil: Record<string, string> = {
      "/to-metadata": "http://169.254.169.254/latest/meta-data/",
      "/to-loopback": "http://127.0.0.1/",
      "/to-decimal": "http://2130706433/",
      "/to-v6": "http://[::ffff:7f00:1]/",
      "/to-internal-dns": "http://internal.example.org/",
      "/to-file": "file:///etc/passwd",
      "/to-port": "http://site.example.org:6379/",
      "/to-localhost": "http://localhost/",
      "/to-creds": "http://u:p@site.example.org/",
    };
    if (evil[url]) {
      res.writeHead(302, { location: evil[url] });
      return void res.end();
    }
    res.writeHead(404);
    res.end("nf");
  });
  await new Promise<void>((r) => server.listen(0, "127.0.0.1", r));
  port = (server.address() as AddressInfo).port;
});
afterAll(() => server.close());

const resolver: Resolver = async (host) => {
  if (host === "internal.example.org") return [{ address: "10.0.0.7", family: 4 }];
  if (host === "mixed.example.org") return [{ address: "93.184.216.34", family: 4 }, { address: "127.0.0.1", family: 4 }];
  throw Object.assign(new Error("nx"), { code: "ENOTFOUND" });
};

const mk = (budget = new ScanBudget()) =>
  createSafeFetcher(budget, { resolver, testRoutes: { "site.example.org": { port } } });
const U = (p: string) => `http://site.example.org${p}`;

describe("safeFetch basics", () => {
  it("fetches body and headers", async () => {
    const r = await mk()(U("/ok"));
    expect(r.status).toBe(200);
    expect(r.body).toContain("hello");
    expect(r.headers["x-test"]).toBe("1");
    expect(r.headers["set-cookie"]).toEqual(["a=1", "b=2"]);
    expect(r.error).toBeUndefined();
  });
  it("follows redirect chains and records each hop", async () => {
    const r = await mk()(U("/chain"));
    expect(r.chain.map((h) => h.status)).toEqual([302, 301, 200]);
    expect(r.finalUrl).toBe(U("/ok"));
  });
  it("does not follow when followRedirects=false", async () => {
    const r = await mk()(U("/to-ok"), { followRedirects: false });
    expect(r.status).toBe(302);
    expect(r.chain).toHaveLength(1);
  });
});

describe("redirect handling", () => {
  it("stops redirect loops", async () => {
    const r = await mk()(U("/loop"));
    expect(r.error?.code).toBe("redirect_loop");
  });
  it("enforces the redirect cap", async () => {
    const r = await mk()(U("/endless"), { maxRedirects: 3 });
    expect(r.error?.code).toBe("too_many_redirects");
    expect(r.chain.length).toBeLessThanOrEqual(4);
  });
  it.each([
    ["/to-metadata", "non_public_ip"],
    ["/to-loopback", "non_public_ip"],
    ["/to-decimal", "non_public_ip"],
    ["/to-v6", "non_public_ip"],
    ["/to-internal-dns", "non_public_ip"],
    ["/to-file", "scheme_not_allowed"],
    ["/to-port", "port_not_allowed"],
    ["/to-localhost", "internal_hostname"],
    ["/to-creds", "credentials_not_allowed"],
  ])("refuses redirect %s", async (path, code) => {
    const before = requests.length;
    const r = await mk()(U(path));
    expect(r.error).toMatchObject({ code, blocked: true });
    expect(r.chain).toHaveLength(1); // only the first hop was fetched
    expect(requests.length - before).toBe(1); // nothing else was requested
  });
  it("refuses a hostname with mixed public/private DNS answers", async () => {
    const r = await mk()("https://mixed.example.org/");
    expect(r.error?.code).toBe("dns_mixed_answers");
  });
  it("refuses direct private targets without any network I/O", async () => {
    const before = requests.length;
    for (const u of ["http://127.0.0.1/", "http://169.254.169.254/", "http://[::1]/", "http://2130706433/"]) {
      expect((await mk()(u)).error?.blocked).toBe(true);
    }
    expect(requests.length).toBe(before);
  });
});

describe("limits", () => {
  it("caps downloaded bytes and marks truncation", async () => {
    const r = await mk()(U("/big"), { maxBytes: 100_000 });
    expect(r.truncated).toBe(true);
    expect(r.bytes).toBeLessThanOrEqual(100_000);
  });
  it("times out requests that never respond", async () => {
    const t = Date.now();
    const r = await mk()(U("/hang"), { timeoutMs: 300 });
    expect(r.error?.code).toBe("ETIMEDOUT");
    expect(Date.now() - t).toBeLessThan(2000);
  });
  it("hard-limits slow-drip responses by wall clock", async () => {
    const t = Date.now();
    const r = await mk()(U("/slow"), { timeoutMs: 400 });
    expect(r.error?.code).toBe("ETIMEDOUT");
    expect(Date.now() - t).toBeLessThan(2000);
  });
  it("enforces the per-scan request budget (redirect hops count)", async () => {
    const f = mk(new ScanBudget(2));
    const r = await f(U("/chain")); // needs 3 requests
    expect(r.error?.code).toBe("request_budget");
    expect((await f(U("/ok"))).error?.code).toBe("request_budget");
  });
  it("enforces the scan deadline", async () => {
    const expired = new ScanBudget(10, 1e6, 1000, Date.now() - 5000); // deadline already passed
    const r = await mk(expired)(U("/ok"));
    expect(r.error?.code).toBe("deadline");
  });
  it("enforces the total byte budget", async () => {
    const f = mk(new ScanBudget(10, 10));
    await f(U("/ok"));
    expect((await f(U("/ok"))).error?.code).toBe("byte_budget");
  });
  it("refuses to be built with test routes in production", () => {
    const prev = process.env.NODE_ENV;
    (process.env as Record<string, string>).NODE_ENV = "production";
    try {
      expect(() => createSafeFetcher(new ScanBudget(), { testRoutes: { "x.example.org": { port } } })).toThrow();
    } finally {
      (process.env as Record<string, string>).NODE_ENV = prev!;
    }
  });
});
