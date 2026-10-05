import type { AddressInfo } from "node:net";
import type http from "node:http";
import { afterEach, beforeAll, describe, expect, it } from "vitest";
import { createNdjsonScanner, ScannerUnavailableError } from "@/lib/jobs/scanner-client";
import { ScanRefusedError, type ScanReport } from "@/lib/scanner/report";

let createServer: typeof import("../server").createServer;
beforeAll(async () => { process.env.VIBESEC_NO_LISTEN = "1"; ({ createServer } = await import("../server")); });

const fakeReport = { version: 1, score: { score: 88 }, findings: [], targets: [], stats: { requests: 3 } } as unknown as ScanReport;
let server: http.Server | null = null;
async function start(scan: Parameters<typeof createServer>[0], inspect?: Parameters<typeof createServer>[1]) {
  server = createServer(scan, inspect);
  await new Promise<void>((r) => server!.listen(0, "127.0.0.1", r));
  const port = (server.address() as AddressInfo).port;
  return { port, client: createNdjsonScanner((req) => fetch(`http://127.0.0.1:${port}${new URL(req.url).pathname}`, { method: req.method, headers: req.headers, body: req.body, duplex: "half" } as RequestInit)), base: `http://127.0.0.1:${port}` };
}
afterEach(() => { server?.close(); server = null; });

describe("container server + NDJSON client", () => {
  it("streams stage events and the final report", async () => {
    const { client } = await start(async (_url, o) => { o?.onStage?.("validating"); o?.onStage?.("scanning_transport"); return fakeReport; });
    const stages: string[] = [];
    const report = await client.scan("https://example.com/", async (s) => void stages.push(s));
    expect(stages).toEqual(["validating", "scanning_transport"]);
    expect(report.score.score).toBe(88);
  });
  it("propagates policy refusals as ScanRefusedError (no retry semantics)", async () => {
    const { client } = await start(async () => { throw new ScanRefusedError("non_public_ip", "nope", "loopback"); });
    await expect(client.scan("http://127.0.0.1/", async () => {})).rejects.toMatchObject({ name: "ScanRefusedError", code: "non_public_ip", detail: "loopback" });
  });
  it("hides internal error text and reports it as unavailable (retryable)", async () => {
    const { client } = await start(async () => { throw new Error("leaky https://target/?token=abc"); });
    const err = await client.scan("https://example.com/", async () => {}).catch((e) => e);
    expect(err).toBeInstanceOf(ScannerUnavailableError);
    expect(String(err.message)).not.toContain("token=abc");
  });
  it("validates the request: bad JSON, missing/oversized url, wrong method/path", async () => {
    const { base } = await start(async () => fakeReport);
    const post = (body: string, path = "/scan") => fetch(base + path, { method: "POST", body });
    expect((await post("not json")).status).toBe(400);
    expect((await post("{}")).status).toBe(400);
    expect((await post(JSON.stringify({ url: "x".repeat(3000) }))).status).toBe(400);
    expect((await post("x".repeat(10_000))).status).toBe(413);
    expect((await post("{}", "/other")).status).toBe(404);
    expect((await fetch(base + "/scan")).status).toBe(404);
    expect((await fetch(base + "/ready")).status).toBe(200);
  });
  it("sheds load with 429 when at capacity (client treats it as retryable)", async () => {
    let release!: () => void;
    const gate = new Promise<void>((r) => (release = r));
    const { base, client } = await start(async () => { await gate; return fakeReport; });
    const inflight = Array.from({ length: 3 }, () => fetch(base + "/scan", { method: "POST", body: JSON.stringify({ url: "https://a.com" }) }));
    await new Promise((r) => setTimeout(r, 100));
    expect((await fetch(base + "/scan", { method: "POST", body: JSON.stringify({ url: "https://a.com" }) })).status).toBe(429);
    await expect(client.scan("https://a.com", async () => {})).rejects.toBeInstanceOf(ScannerUnavailableError);
    release();
    await Promise.all(inflight.map(async (p) => (await p).text()));
  });
});

describe("NDJSON client robustness", () => {
  const streamOf = (chunks: string[]) => new Response(new ReadableStream({ start(c) { for (const x of chunks) c.enqueue(new TextEncoder().encode(x)); c.close(); } }));
  it("reassembles lines split across chunk boundaries", async () => {
    const line = JSON.stringify({ t: "report", report: fakeReport }) + "\n";
    const c = createNdjsonScanner(async () => streamOf([JSON.stringify({ t: "stage", stage: "validating" }).slice(0, 7), JSON.stringify({ t: "stage", stage: "validating" }).slice(7) + "\n", line.slice(0, 20), line.slice(20)]));
    const stages: string[] = [];
    expect((await c.scan("u", async (s) => void stages.push(s))).score.score).toBe(88);
    expect(stages).toEqual(["validating"]);
  });
  it.each([
    ["ends without a report", [JSON.stringify({ t: "stage", stage: "x" }) + "\n"]],
    ["malformed output", ["{not json\n"]],
    ["explicit error line", [JSON.stringify({ t: "error", message: "boom" }) + "\n"]],
  ])("treats a stream that %s as unavailable", async (_n, chunks) => {
    await expect(createNdjsonScanner(async () => streamOf(chunks)).scan("u", async () => {})).rejects.toBeInstanceOf(ScannerUnavailableError);
  });
  it("caps response size and handles transport failure / 5xx", async () => {
    await expect(createNdjsonScanner(async () => streamOf(["x".repeat(9 * 1024 * 1024)])).scan("u", async () => {})).rejects.toBeInstanceOf(ScannerUnavailableError);
    await expect(createNdjsonScanner(async () => { throw new Error("connect"); }).scan("u", async () => {})).rejects.toBeInstanceOf(ScannerUnavailableError);
    await expect(createNdjsonScanner(async () => new Response("", { status: 503 })).scan("u", async () => {})).rejects.toBeInstanceOf(ScannerUnavailableError);
  });
});

describe("container POST /tls", () => {
  it("trả JSON kết quả kiểm tra TLS", async () => {
    const { base } = await start(async () => fakeReport, async () => ({ ok: true, tls: { protocol: "TLSv1.3", cipher: "x", authorized: true }, legacyTls: { tls10: false, tls11: false, h2: true }, resolved: ["93.184.216.34"] }));
    const r = await fetch(`${base}/tls`, { method: "POST", body: JSON.stringify({ host: "example.com" }) });
    expect(await r.json()).toMatchObject({ ok: true, tls: { protocol: "TLSv1.3" }, legacyTls: { h2: true } });
  });
  it("host nội bộ → refused (không phải 500)", async () => {
    const { SsrfError } = await import("@/lib/ssrf/url");
    const { base } = await start(async () => fakeReport, async () => { throw new SsrfError("non_public_ip", "nội bộ"); });
    const r = await fetch(`${base}/tls`, { method: "POST", body: JSON.stringify({ host: "10.0.0.1" }) });
    expect(await r.json()).toMatchObject({ ok: false, refused: { code: "non_public_ip" } });
  });
  it("host thiếu/không hợp lệ → 400; lỗi nội bộ → 500", async () => {
    const { base } = await start(async () => fakeReport, async () => { throw new Error("boom"); });
    expect((await fetch(`${base}/tls`, { method: "POST", body: "{}" })).status).toBe(400);
    expect((await fetch(`${base}/tls`, { method: "POST", body: JSON.stringify({ host: "example.com" }) })).status).toBe(500);
  });
});
