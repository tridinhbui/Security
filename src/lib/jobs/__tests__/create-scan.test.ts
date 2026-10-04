import { beforeEach, describe, expect, it } from "vitest";
import { createTestD1, seedUser } from "@/lib/db/__tests__/test-d1";
import * as repo from "@/lib/db/repo";
import type { Resolver } from "@/lib/ssrf/dns";
import { createScan } from "../create-scan";

let db: ReturnType<typeof createTestD1>;
let user: string;
const pub: Resolver = async () => [{ address: "93.184.216.34", family: 4 }];
const nxdomain: Resolver = async () => { throw Object.assign(new Error("nx"), { code: "ENOTFOUND" }); };
const dohDown: Resolver = async () => { throw Object.assign(new Error("doh"), { code: "EDOH" }); };
const scanCount = () => (db.sqlite.prepare("SELECT COUNT(*) c FROM scans").get() as { c: number }).c;

beforeEach(async () => { db = createTestD1(); user = await seedUser(db, "u@x.com"); });

describe("createScan", () => {
  it.each([
    ["http://127.0.0.1/", "non_public_ip"], ["http://169.254.169.254/", "non_public_ip"], ["localhost", "internal_hostname"],
    ["file:///etc/passwd", "scheme_not_allowed"], ["https://example.com:8080", "port_not_allowed"], ["http://2130706433", "non_public_ip"],
    ["http://[::ffff:7f00:1]/", "non_public_ip"], ["https://user:pw@example.com", "credentials_not_allowed"],
  ])("rejects %s before queueing and logs an SSRF strike", async (url, code) => {
    const r = await createScan(db, user, url, "h", pub);
    expect(r).toMatchObject({ ok: false, status: 400, code });
    expect(scanCount()).toBe(0);
    expect(await repo.countEvents(db, user, "ssrf_blocked", 60_000)).toBe(1);
  });

  it("rejects hostnames that resolve to private space (preflight DNS)", async () => {
    const priv: Resolver = async () => [{ address: "10.1.2.3", family: 4 }];
    expect(await createScan(db, user, "https://intranet.example.org", "h", priv)).toMatchObject({ ok: false, code: "non_public_ip" });
    const mixed: Resolver = async () => [{ address: "93.184.216.34", family: 4 }, { address: "127.0.0.1", family: 4 }];
    expect(await createScan(db, user, "https://mixed.example.org", "h", mixed)).toMatchObject({ ok: false, code: "dns_mixed_answers" });
    expect(scanCount()).toBe(0);
  });

  it("NXDOMAIN is a clean 400 without an abuse strike; a flaky resolver does not block the scan", async () => {
    expect(await createScan(db, user, "https://no-such-site.example.org", "h", nxdomain)).toMatchObject({ ok: false, status: 400, code: "dns_failed" });
    expect(await repo.countEvents(db, user, "ssrf_blocked", 60_000)).toBe(0);
    expect((await createScan(db, user, "https://real-site.example.org", "h", dohDown)).ok).toBe(true); // container re-validates
  });

  it("suspends the account after repeated strikes", async () => {
    for (let i = 0; i < 5; i++) await createScan(db, user, `http://10.0.0.${i}/`, "h", pub);
    expect(await createScan(db, user, "https://example.com", "h", pub)).toMatchObject({ ok: false, status: 403, code: "account_blocked" });
  });

  it("stores only the normalized URL — query strings and fragments never reach the DB or logs", async () => {
    const r = await createScan(db, user, "Example.com/Path?token=SECRET123#frag", "h", pub);
    expect(r.ok).toBe(true);
    const row = db.sqlite.prepare("SELECT input_url, normalized_url, host FROM scans").get() as Record<string, string>;
    expect(row).toEqual({ input_url: "https://example.com/Path", normalized_url: "https://example.com/Path", host: "example.com" });
    await createScan(db, user, "http://127.0.0.1/?token=SECRET123", "h", pub);
    expect(JSON.stringify(db.sqlite.prepare("SELECT * FROM scan_events").all())).not.toContain("SECRET123");
  });

  it.each([["daily_quota", { SCAN_DAILY_QUOTA: "1" }], ["hourly_limit", { SCAN_HOURLY_LIMIT: "1" }], ["too_many_concurrent", { SCAN_MAX_CONCURRENT_PER_USER: "1" }], ["host_limit", { SCAN_HOST_HOURLY_LIMIT: "1" }]])(
    "maps %s → HTTP 429 and audits it", async (code, envVars) => {
      Object.assign(process.env, envVars);
      try {
        expect((await createScan(db, user, "https://example.com", "h", pub)).ok).toBe(true);
        if (code !== "too_many_concurrent") db.sqlite.exec("UPDATE scans SET status='completed'"); // concurrency case keeps the first scan running
        const r = await createScan(db, user, "https://example.com", "h", pub);
        expect(r).toMatchObject({ ok: false, status: 429 });
        expect(await repo.countEvents(db, user, "rate_limited", 60_000)).toBe(1);
      } finally { for (const k of Object.keys(envVars)) delete process.env[k]; }
    });
});
