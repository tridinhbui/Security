import { beforeEach, describe, expect, it } from "vitest";
import type { Finding } from "@/lib/scanner/types";
import { makeFinding } from "@/lib/scanner/util";
import * as repo from "../repo";
import { createTestD1, seedUser } from "./test-d1";

let db: ReturnType<typeof createTestD1>;
let u1: string, u2: string;
const LIM = { maxConcurrent: 2, hourly: 8, daily: 20, ipHourly: 15, hostHourly: 4 };
const create = (userId: string, host: string, over: Partial<typeof LIM> = {}, ip: string | null = "ip1") =>
  repo.createScanChecked(db, { userId, url: `https://${host}/`, host, ipHash: ip, limits: { ...LIM, ...over } });
const finishAll = () => db.sqlite.exec("UPDATE scans SET status='completed', completed_at=created_at");

beforeEach(async () => {
  db = createTestD1();
  u1 = await seedUser(db, "a@x.com");
  u2 = await seedUser(db, "b@x.com");
});

describe("createScanChecked — atomic limits", () => {
  it("enqueues and enforces per-user concurrency", async () => {
    expect((await create(u1, "a.com")).ok).toBe(true);
    expect((await create(u1, "b.com")).ok).toBe(true);
    expect(await create(u1, "c.com")).toMatchObject({ ok: false, code: "too_many_concurrent" });
    expect(await create(u2, "c.com")).toMatchObject({ ok: true }); // other users unaffected
  });
  it("hourly and daily limits", async () => {
    for (const h of ["a", "b", "c", "d", "e", "f"]) await create(u1, `${h}.com`, { maxConcurrent: 99 });
    finishAll();
    expect(await create(u1, "z.com", { hourly: 6, maxConcurrent: 99 })).toMatchObject({ code: "hourly_limit" });
    expect(await create(u1, "z.com", { hourly: 99, daily: 6, maxConcurrent: 99 })).toMatchObject({ code: "daily_quota" });
  });
  it("per-IP limit applies across accounts", async () => {
    for (const h of ["a", "b", "c"]) { await create(u1, `${h}.com`, { maxConcurrent: 99 }, "shared-ip"); }
    finishAll();
    expect(await create(u2, "d.com", { ipHourly: 3 }, "shared-ip")).toMatchObject({ code: "ip_limit" });
    expect(await create(u2, "d.com", { ipHourly: 3 }, null)).toMatchObject({ ok: true }); // no IP known → rule skipped
  });
  it("per-target-host limit protects the scanned site across all users", async () => {
    for (let i = 0; i < 3; i++) { await create(i % 2 ? u1 : u2, "victim.com", { hostHourly: 99, maxConcurrent: 99 }, `ip${i}`); finishAll(); }
    expect(await create(u1, "victim.com", { hostHourly: 3 }, "ipX")).toMatchObject({ code: "host_limit" });
    expect(await create(u1, "other.com", { hostHourly: 3 }, "ipX")).toMatchObject({ ok: true });
  });
  it("blocked accounts cannot scan until the block expires", async () => {
    await repo.blockUser(db, u1, new Date(Date.now() + 86_400_000).toISOString());
    expect(await create(u1, "a.com")).toMatchObject({ ok: false, code: "account_blocked" });
    await repo.blockUser(db, u1, new Date(Date.now() - 1000).toISOString());
    expect((await create(u1, "a.com")).ok).toBe(true);
  });
  it("concurrent requests cannot exceed the limit (atomicity)", async () => {
    const results = await Promise.all(Array.from({ length: 10 }, (_, i) => create(u1, `p${i}.com`, { maxConcurrent: 3, hostHourly: 99 })));
    expect(results.filter((r) => r.ok)).toHaveLength(3);
  });
});

describe("ownership isolation (replaces RLS)", () => {
  it("users only see, load and delete their own scans", async () => {
    const a = (await create(u1, "a.com")) as { id: string };
    expect(await repo.getScan(db, u1, a.id)).not.toBeNull();
    expect(await repo.getScan(db, u2, a.id)).toBeNull();
    expect(await repo.listScans(db, u2, 50)).toHaveLength(0);
    expect(await repo.deleteScan(db, u2, a.id)).toBe(false);
    expect(await repo.getScan(db, u1, a.id)).not.toBeNull();
    expect(await repo.deleteScan(db, u1, a.id)).toBe(true);
  });
  it("critical-findings lookup cannot read another user's findings", async () => {
    const a = (await create(u1, "a.com")) as { id: string };
    await completeWith(a.id, [makeFinding({ ruleId: "r", title: "bad", category: "Headers", severity: "high", confidence: "high", status: "fail", summary: "s", explanation: "e" })]);
    expect(await repo.openCriticalFindings(db, u1, [a.id])).toHaveLength(1);
    expect(await repo.openCriticalFindings(db, u2, [a.id])).toHaveLength(0);
  });
  it("revoking shares only affects the owner's links", async () => {
    const a = (await create(u1, "a.com")) as { id: string };
    await repo.createShare(db, { scanId: a.id, userId: u1, tokenHash: "h1", expiresAt: null });
    expect(await repo.revokeShares(db, u2, a.id)).toBe(0);
    expect(await repo.revokeShares(db, u1, a.id)).toBe(1);
    expect(await repo.getShareByHash(db, "h1")).toBeNull();
  });
  it("deleteAllScans only removes the caller's scans", async () => {
    await create(u1, "a.com"); await create(u2, "b.com");
    expect(await repo.deleteAllScans(db, u1)).toBe(1);
    expect(await repo.listScans(db, u2, 10)).toHaveLength(1);
  });
});

async function completeWith(id: string, findings: Finding[]) {
  await repo.claimScan(db, id);
  await repo.completeScan(db, id, { score: 70, grade: "C", categoryScores: { Headers: 80 }, severityCounts: { critical: 0, high: 1, medium: 0, low: 0, info: 0 }, platforms: ["nextjs"], requests: 9, retentionDays: 90, findings, targets: [{ role: "https_home", url: "https://a.com/", finalUrl: "https://a.com/", status: 200, tls: { protocol: "TLSv1.3" }, headersEnc: "enc", resolved: ["1.2.3.4"], errorCode: null, durationMs: 5 }] });
}

describe("queue lifecycle", () => {
  it("claim is exclusive and idempotent for redelivered messages", async () => {
    const a = (await create(u1, "a.com")) as { id: string };
    const first = await repo.claimScan(db, a.id);
    expect(first).toMatchObject({ status: "validating", attempts: 1 });
    expect(await repo.claimScan(db, a.id)).toBeNull(); // duplicate delivery: someone is running it
  });
  it("a scan whose worker died (stale heartbeat) can be re-claimed", async () => {
    const a = (await create(u1, "a.com")) as { id: string };
    await repo.claimScan(db, a.id);
    db.sqlite.prepare("UPDATE scans SET locked_at = ?").run(new Date(Date.now() - 10 * 60_000).toISOString());
    expect(await repo.claimScan(db, a.id)).toMatchObject({ attempts: 2 });
  });
  it("completed/failed scans are never re-claimed or moved by stage updates", async () => {
    const a = (await create(u1, "a.com")) as { id: string };
    await repo.claimScan(db, a.id);
    await repo.failScan(db, a.id, "unreachable", "x");
    expect(await repo.claimScan(db, a.id)).toBeNull();
    await repo.setScanStage(db, a.id, "scanning_transport");
    expect((await repo.getScan(db, u1, a.id))!.status).toBe("failed");
  });
  it("completeScan persists JSON fields and sets expiry from retention", async () => {
    const a = (await create(u1, "a.com")) as { id: string };
    await completeWith(a.id, [makeFinding({ ruleId: "r", title: "t", category: "Headers", severity: "low", confidence: "high", status: "fail", summary: "s", explanation: "e", evidence: ["x: y"], references: [{ title: "T", url: "https://u" }], affectedUrl: "https://a.com/" })]);
    const s = (await repo.getScan(db, u1, a.id))!;
    expect(s).toMatchObject({ status: "completed", score: 70, grade: "C", request_count: 9 });
    expect(s.category_scores).toEqual({ Headers: 80 });
    expect(s.platforms).toEqual(["nextjs"]);
    const days = (Date.parse(s.expires_at!) - Date.parse(s.completed_at!)) / 86_400_000;
    expect(Math.round(days)).toBe(90);
    const [f] = await repo.listFindings(db, a.id);
    expect(f).toMatchObject({ rule_id: "r", evidence: ["x: y"], references: [{ title: "T", url: "https://u" }] });
  });
  it("completeScan is transactional: a failure leaves no partial findings", async () => {
    const a = (await create(u1, "a.com")) as { id: string };
    await repo.claimScan(db, a.id);
    const bad = makeFinding({ ruleId: "r", title: "t", category: "Headers", severity: "low", confidence: "high", status: "fail", summary: "s", explanation: "e" });
    await expect(repo.completeScan(db, a.id, { score: 999 /* violates CHECK */, grade: "A", categoryScores: {}, severityCounts: {}, platforms: [], requests: 1, retentionDays: 90, findings: [bad], targets: [] })).rejects.toThrow();
    expect(await repo.listFindings(db, a.id)).toHaveLength(0);
  });
  it("cron helpers: stale queued ids, hung scans failed", async () => {
    const q = (await create(u1, "q.com")) as { id: string };
    db.sqlite.prepare("UPDATE scans SET created_at = ? WHERE id = ?").run(new Date(Date.now() - 5 * 60_000).toISOString(), q.id);
    expect(await repo.staleQueued(db, 2 * 60_000)).toEqual([q.id]);
    const h = (await create(u2, "h.com")) as { id: string };
    await repo.claimScan(db, h.id);
    db.sqlite.prepare("UPDATE scans SET locked_at = ? WHERE id = ?").run(new Date(Date.now() - 20 * 60_000).toISOString(), h.id);
    expect(await repo.reapHung(db, 10 * 60_000)).toBe(1);
    expect((await repo.getScanInternal(db, h.id))!.error_code).toBe("timeout");
  });
});

describe("retention & purge", () => {
  it("changing retention re-dates existing completed reports", async () => {
    const a = (await create(u1, "a.com")) as { id: string };
    await completeWith(a.id, []);
    await repo.setRetention(db, u1, 7);
    const s = (await repo.getScan(db, u1, a.id))!;
    expect(Math.round((Date.parse(s.expires_at!) - Date.parse(s.completed_at!)) / 86_400_000)).toBe(7);
    expect((await repo.getUserById(db, u1))!.retention_days).toBe(7);
  });
  it("rejects invalid retention values at the DB level", async () => {
    expect(() => db.sqlite.prepare("UPDATE users SET retention_days = 5").run()).toThrow();
  });
  it("purge deletes expired reports and cascades findings/targets/shares", async () => {
    const a = (await create(u1, "a.com")) as { id: string };
    await completeWith(a.id, [makeFinding({ ruleId: "r", title: "t", category: "Headers", severity: "low", confidence: "high", status: "fail", summary: "s", explanation: "e" })]);
    await repo.createShare(db, { scanId: a.id, userId: u1, tokenHash: "tok", expiresAt: null });
    db.sqlite.prepare("UPDATE scans SET expires_at = ?").run(new Date(Date.now() - 1000).toISOString());
    expect((await repo.purgeExpired(db)).scans).toBe(1);
    for (const t of ["findings", "scan_targets", "report_shares"]) expect((db.sqlite.prepare(`SELECT COUNT(*) c FROM ${t}`).get() as { c: number }).c).toBe(0);
  });
  it("deleting a user's scan keeps audit events but detaches them (events cascade with scan)", async () => {
    const a = (await create(u1, "a.com")) as { id: string };
    await repo.recordEvent(db, { type: "scan_created", scanId: a.id, userId: u1 });
    await repo.deleteScan(db, u1, a.id);
    expect(await repo.countEvents(db, u1, "scan_created", 60_000)).toBe(0);
  });
});

describe("sessions & throttling", () => {
  it("sessions expire and are scoped to their user", async () => {
    await repo.insertSession(db, "h-live", u1, new Date(Date.now() + 60_000).toISOString());
    await repo.insertSession(db, "h-dead", u1, new Date(Date.now() - 60_000).toISOString());
    expect((await repo.getSessionUser(db, "h-live"))!.id).toBe(u1);
    expect(await repo.getSessionUser(db, "h-dead")).toBeNull();
    expect(await repo.getSessionUser(db, "nope")).toBeNull();
    await repo.deleteUserSessions(db, u1);
    expect(await repo.getSessionUser(db, "h-live")).toBeNull();
  });
  it("attempt counters respect the window", async () => {
    await repo.recordAttempt(db, "login_fail_email", "k");
    await repo.recordAttempt(db, "login_fail_email", "k");
    expect(await repo.countAttempts(db, "login_fail_email", "k", 60_000)).toBe(2);
    expect(await repo.countAttempts(db, "login_fail_ip", "k", 60_000)).toBe(0);
    db.sqlite.prepare("UPDATE auth_attempts SET at = ?").run(new Date(Date.now() - 3_600_000).toISOString());
    expect(await repo.countAttempts(db, "login_fail_email", "k", 60_000)).toBe(0);
  });
  it("duplicate email is reported, not thrown", async () => {
    expect(await repo.createUser(db, "a@x.com", "h")).toEqual({ ok: false, reason: "exists" });
  });
});

describe("metrics", () => {
  it("reports queue depth and error rate without scan content", async () => {
    await create(u1, "a.com");
    await repo.recordEvent(db, { type: "scan_completed", userId: u1, meta: { latency_ms: 1200 } });
    await repo.recordEvent(db, { type: "scan_failed", userId: u1 });
    const m = await repo.metrics(db);
    expect(m.queue_depth).toBe(1);
    expect(m.last_hour.failed).toBe(1);
    expect(m.worker_latency_ms.p50).toBe(1200);
  });
});
