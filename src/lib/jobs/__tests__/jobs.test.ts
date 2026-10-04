import http from "node:http";
import { randomBytes } from "node:crypto";
import type { AddressInfo } from "node:net";
import { afterAll, beforeAll, beforeEach, describe, expect, it } from "vitest";
import { decrypt } from "@/lib/crypto";
import { createTestD1, seedUser } from "@/lib/db/__tests__/test-d1";
import * as repo from "@/lib/db/repo";
import { runScan } from "@/lib/scanner/engine";
import type { Resolver } from "@/lib/ssrf/dns";
import { processScanJob, MAX_ATTEMPTS } from "../run-scan-job";
import { ScannerUnavailableError, type ScannerClient } from "../scanner-client";

const SECRET = "sk_live_" + "Q9w8E7r6T5y4U3i2O1p0A9s8";
const COOKIE_VALUE = "SESSIONVALUE123456";
let server: http.Server;
let port: number;
let db: ReturnType<typeof createTestD1>;
let user: string;

beforeAll(async () => {
  process.env.DATA_ENCRYPTION_KEY = randomBytes(32).toString("base64");
  process.env.IP_HASH_SECRET = "ip-secret";
  server = http.createServer((req, res) => {
    if (req.url === "/") {
      res.writeHead(200, { "content-type": "text/html", "set-cookie": `session=${COOKIE_VALUE}; Path=/` });
      return void res.end(`<html><script src="/a.js"></script><body>hi</body></html>`);
    }
    if (req.url === "/a.js") { res.writeHead(200, { "content-type": "application/javascript" }); return void res.end(`var k="${SECRET}";`); }
    res.writeHead(404).end();
  });
  await new Promise<void>((r) => server.listen(0, "127.0.0.1", r));
  port = (server.address() as AddressInfo).port;
});
afterAll(() => server.close());
beforeEach(async () => { db = createTestD1(); user = await seedUser(db, "u@x.com"); });

const nx: Resolver = async () => { throw Object.assign(new Error("nx"), { code: "ENOTFOUND" }); };
/** In-process stand-in for the container: runs the REAL scanner engine against the local fixture site. */
const realScanner: ScannerClient = {
  scan: (url, onStage) => runScan(url, { resolver: nx, testRoutes: { "site.example.org": { port } }, onStage, collectOverrides: { lookupDns: async () => ({ domain: "example.org", caa: [], spf: null, dmarc: null }) } }),
};
async function enqueue(url: string) {
  const r = await repo.createScanChecked(db, { userId: user, url, host: new URL(url).hostname, ipHash: null, limits: { maxConcurrent: 99, hourly: 99, daily: 99, ipHourly: 99, hostHourly: 99 } });
  if (!r.ok) throw new Error("enqueue failed");
  return r.id;
}

describe("processScanJob — happy path", () => {
  it("scans, persists findings/targets, and never stores secrets or cookie values", async () => {
    const id = await enqueue("http://site.example.org/");
    expect(await processScanJob(db, id, realScanner)).toBe("done");

    const scan = (await repo.getScan(db, user, id))!;
    expect(scan).toMatchObject({ status: "completed", grade: "F" }); // live secret → Critical → capped
    expect(scan.score).toBeLessThanOrEqual(59);
    expect(scan.expires_at).toBeTruthy();

    const findings = await repo.listFindings(db, id);
    expect(findings.find((f) => f.rule_id === "exposure.secrets")).toMatchObject({ status: "fail", severity: "critical" });

    // Nothing sensitive anywhere in the database.
    const dump = JSON.stringify(["users", "scans", "scan_targets", "findings", "scan_events"].map((t) => db.sqlite.prepare(`SELECT * FROM ${t}`).all()));
    expect(dump).not.toContain(SECRET);
    expect(dump).not.toContain(COOKIE_VALUE);

    // Raw headers are encrypted at rest and cookie values redacted inside them.
    const targets = await repo.listTargetsRaw(db, id);
    expect(targets.every((x) => x.headers_enc!.startsWith("v1:"))).toBe(true);
    const home = targets.find((x) => x.role === "http_home")!;
    const headers = JSON.parse(await decrypt(home.headers_enc!));
    expect(headers["set-cookie"]).toEqual(["session=<đã che>; Path=/"]);

    // Observability events were written.
    const events = db.sqlite.prepare("SELECT type FROM scan_events WHERE scan_id = ?").all(id).map((r) => (r as { type: string }).type);
    expect(events).toContain("stage");
    expect(events).toContain("scan_completed");
  });

  it("is idempotent: a duplicate or redelivered message is skipped", async () => {
    const id = await enqueue("http://site.example.org/");
    expect(await processScanJob(db, id, realScanner)).toBe("done");
    expect(await processScanJob(db, id, realScanner)).toBe("skipped");
    expect((db.sqlite.prepare("SELECT COUNT(*) c FROM findings WHERE scan_id = ?").get(id) as { c: number }).c).toBeGreaterThan(0);
    const [n] = db.sqlite.prepare("SELECT COUNT(*) c FROM findings WHERE rule_id = 'exposure.secrets' AND scan_id = ?").all(id) as { c: number }[];
    expect(n!.c).toBe(1);
  });

  it("respects the user's retention setting", async () => {
    await repo.setRetention(db, user, 7);
    const id = await enqueue("http://site.example.org/");
    await processScanJob(db, id, realScanner);
    const s = (await repo.getScan(db, user, id))!;
    expect(Math.round((Date.parse(s.expires_at!) - Date.parse(s.completed_at!)) / 86_400_000)).toBe(7);
  });
});

describe("processScanJob — refusals and abuse", () => {
  it("fails permanently (no retry) when the target is refused, and records an SSRF strike", async () => {
    const id = await enqueue("https://10.0.0.5/");
    expect(await processScanJob(db, id, realScanner)).toBe("done");
    expect(await repo.getScan(db, user, id)).toMatchObject({ status: "failed", error_code: "non_public_ip" });
    expect(await repo.countEvents(db, user, "ssrf_blocked", 60_000)).toBe(1);
  });
  it("suspends the account after repeated blocked targets", async () => {
    for (let i = 0; i < 5; i++) await processScanJob(db, await enqueue(`https://10.0.0.${i + 1}/`), realScanner);
    const u = (await repo.getUserById(db, user))!;
    expect(u.blocked_until && u.blocked_until > new Date().toISOString()).toBeTruthy();
    expect(await repo.createScanChecked(db, { userId: user, url: "https://a.com/", host: "a.com", ipHash: null, limits: { maxConcurrent: 9, hourly: 9, daily: 9, ipHourly: 9, hostHourly: 9 } })).toMatchObject({ ok: false, code: "account_blocked" });
  });
  it("'unreachable' is a normal failure, not an abuse strike", async () => {
    const dead = http.createServer(); await new Promise<void>((r) => dead.listen(0, "127.0.0.1", r));
    const p = (dead.address() as AddressInfo).port; await new Promise<void>((r) => dead.close(() => r()));
    const scanner: ScannerClient = { scan: (url, onStage) => runScan(url, { resolver: nx, testRoutes: { "down.example.org": { port: p } }, onStage }) };
    const id = await enqueue("http://down.example.org/");
    await processScanJob(db, id, scanner);
    expect(await repo.getScan(db, user, id)).toMatchObject({ status: "failed", error_code: "unreachable" });
    expect(await repo.countEvents(db, user, "ssrf_blocked", 60_000)).toBe(0);
  });
});

describe("processScanJob — infrastructure failures", () => {
  const down: ScannerClient = { scan: async () => { throw new ScannerUnavailableError("container down"); } };
  it("asks for a retry and re-queues the scan until attempts are exhausted, then fails it", async () => {
    const id = await enqueue("https://example.com/");
    for (let attempt = 1; attempt < MAX_ATTEMPTS; attempt++) {
      expect(await processScanJob(db, id, down)).toBe("retry");
      expect((await repo.getScan(db, user, id))!.status).toBe("queued");
    }
    expect(await processScanJob(db, id, down)).toBe("done");
    expect(await repo.getScan(db, user, id)).toMatchObject({ status: "failed", error_code: "internal_error" });
    expect(await repo.metrics(db)).toMatchObject({ last_hour: { failed: 1 } });
  });
  it("an unexpected crash is contained and never leaks its message to the user", async () => {
    const id = await enqueue("https://example.com/");
    const crash: ScannerClient = { scan: async () => { throw new Error("secret internal detail https://target/?token=abc"); } };
    expect(await processScanJob(db, id, crash)).toBe("done");
    const s = (await repo.getScan(db, user, id))!;
    expect(s.error_message).not.toContain("token=abc");
    expect(JSON.stringify(db.sqlite.prepare("SELECT * FROM scan_events").all())).not.toContain("token=abc");
  });
  it("stage updates cannot resurrect a finished scan", async () => {
    const id = await enqueue("https://example.com/");
    const slow: ScannerClient = { scan: async (_u, onStage) => { await repo.failScan(db, id, "timeout", "x"); await onStage("scanning_transport"); throw new ScannerUnavailableError("late"); } };
    await processScanJob(db, id, slow);
    expect((await repo.getScan(db, user, id))!.status).toBe("failed");
  });
});
