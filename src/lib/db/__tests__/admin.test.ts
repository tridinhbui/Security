import { beforeEach, describe, expect, it } from "vitest";
import * as repo from "../repo";
import { createTestD1, seedUser } from "./test-d1";

let db: ReturnType<typeof createTestD1>;
let u1: string, u2: string;
beforeEach(async () => { db = createTestD1(); u1 = await seedUser(db, "a@x.com"); u2 = await seedUser(db, "b@x.com"); });
const setSeen = (id: string, iso: string) => db.sqlite.prepare("UPDATE users SET last_seen_at=? WHERE id=?").run(iso, id);
const usage = (id: string) => (db.sqlite.prepare("SELECT usage_seconds u FROM users WHERE id=?").get(id) as { u: number }).u;

describe("touchActivity — thời lượng sử dụng", () => {
  it("cộng khoảng cách khi ≤ 5 phút, bỏ qua khi nghỉ lâu", async () => {
    setSeen(u1, new Date(Date.now() - 120_000).toISOString());
    await repo.touchActivity(db, u1);
    expect(usage(u1)).toBeGreaterThanOrEqual(119);
    expect(usage(u1)).toBeLessThanOrEqual(122);
    const before = usage(u1);
    setSeen(u1, new Date(Date.now() - 3_600_000).toISOString());
    await repo.touchActivity(db, u1);
    expect(usage(u1)).toBe(before);
  });
  it("giới hạn ghi: gọi lại trong 30 giây không đổi gì", async () => {
    await repo.touchActivity(db, u1);
    const seen = (db.sqlite.prepare("SELECT last_seen_at s FROM users WHERE id=?").get(u1) as { s: string }).s;
    await repo.touchActivity(db, u1);
    expect((db.sqlite.prepare("SELECT last_seen_at s FROM users WHERE id=?").get(u1) as { s: string }).s).toBe(seen);
    expect(usage(u1)).toBe(0);
  });
});

describe("chat hỗ trợ", () => {
  it("luồng chat tách theo người dùng; đã đọc theo từng phía", async () => {
    await repo.sendChat(db, u1, "user", "xin chào");
    await repo.sendChat(db, u2, "user", "của người khác");
    expect((await repo.listChat(db, u1)).map((m) => m.body)).toEqual(["xin chào"]);
    expect((await repo.adminListUsers(db)).find((u) => u.id === u1)!.unread).toBe(1);
    await repo.markChatRead(db, u1, "admin");
    expect((await repo.adminListUsers(db)).find((u) => u.id === u1)!.unread).toBe(0);
    await repo.sendChat(db, u1, "admin", "chào bạn");
    expect(await repo.unreadAdminReplies(db, u1)).toBe(1);
    await repo.markChatRead(db, u1, "user");
    expect(await repo.unreadAdminReplies(db, u1)).toBe(0);
  });
  it("cắt tin quá dài và xoá theo khi xoá người dùng", async () => {
    const m = await repo.sendChat(db, u1, "user", "x".repeat(5000));
    expect(m.body).toHaveLength(repo.CHAT_MAX_LEN);
    db.sqlite.prepare("DELETE FROM users WHERE id=?").run(u1);
    expect(await repo.listChat(db, u1)).toHaveLength(0);
  });
});

describe("admin", () => {
  it("tổng quan, danh sách trang đã quét, kiểm tra liên kết Google", async () => {
    await repo.createScanChecked(db, { userId: u1, url: "https://site.com/", host: "site.com", ipHash: null, limits: { maxConcurrent: 9, hourly: 9, daily: 9, monthly: 9, globalDaily: 99, ipHourly: 9, hostHourly: 9 } });
    const o = await repo.adminOverview(db);
    expect(o).toMatchObject({ users: 2, scansTotal: 1, scans24h: 1 });
    expect((await repo.adminUserScans(db, u1)).map((s) => s.normalized_url)).toEqual(["https://site.com/"]);
    expect(await repo.adminUserScans(db, u2)).toEqual([]);
    expect(await repo.hasGoogleLink(db, u1)).toBe(false);
    db.sqlite.prepare("UPDATE users SET google_sub='g1' WHERE id=?").run(u1);
    expect(await repo.hasGoogleLink(db, u1)).toBe(true);
  });
});

describe("cloneRecentScan — dùng lại kết quả", () => {
  const L = { maxConcurrent: 9, hourly: 9, daily: 9, monthly: 9, globalDaily: 99, ipHourly: 9, hostHourly: 9 };
  async function completed(user: string, url = "https://site.com/") {
    const r = await repo.createScanChecked(db, { userId: user, url, host: "site.com", ipHash: null, limits: L });
    if (!r.ok) throw new Error("x");
    db.sqlite.prepare("UPDATE scans SET status='completed', score=80, grade='B', completed_at=? WHERE id=?").run(new Date().toISOString(), r.id);
    db.sqlite.prepare("INSERT INTO findings (id,scan_id,rule_id,fingerprint,title,category,severity,confidence,status,explanation,summary) VALUES ('f1',?,'r','fp','t','Headers','low','high','fail','e','s')").run(r.id);
    return r.id;
  }
  it("sao chép kết quả của người khác, không tính hạn mức", async () => {
    await completed(u1);
    const id = await repo.cloneRecentScan(db, { userId: u2, url: "https://site.com/", host: "site.com", ipHash: null });
    expect(id).toBeTruthy();
    expect(db.sqlite.prepare("SELECT cached, score, user_id FROM scans WHERE id=?").get(id!)).toMatchObject({ cached: 1, score: 80, user_id: u2 });
    expect(db.sqlite.prepare("SELECT COUNT(*) c FROM findings WHERE scan_id=?").get(id!)).toMatchObject({ c: 1 });
    // chỉ 1 lượt quét thật được tính
    expect(await repo.createScanChecked(db, { userId: u2, url: "https://other.com/", host: "other.com", ipHash: null, limits: { ...L, hourly: 1, globalDaily: 2 } })).toMatchObject({ ok: true });
  });
  it("chính chủ quét lại ngay sau khi quét: dùng lại ≤ 15 phút, sau đó quét thật", async () => {
    await completed(u1);
    expect(await repo.cloneRecentScan(db, { userId: u1, url: "https://site.com/", host: "site.com", ipHash: null })).toBeTruthy();
    db.sqlite.prepare("UPDATE scans SET completed_at=?").run(new Date(Date.now() - 3_600_000).toISOString());
    expect(await repo.cloneRecentScan(db, { userId: u1, url: "https://site.com/", host: "site.com", ipHash: null })).toBeNull();
  });
  it("không có kết quả gần đây → null", async () => {
    expect(await repo.cloneRecentScan(db, { userId: u2, url: "https://none.com/", host: "none.com", ipHash: null })).toBeNull();
  });
  it("quét nhanh có thể dùng lại kết quả đầy đủ, nhưng quét đầy đủ không dùng lại kết quả nhanh", async () => {
    const r = await repo.createScanChecked(db, { userId: u1, url: "https://q.com/", host: "q.com", ipHash: null, limits: L, mode: "quick" });
    if (!r.ok) throw new Error("x");
    db.sqlite.prepare("UPDATE scans SET status='completed', score=70, grade='C', completed_at=? WHERE id=?").run(new Date().toISOString(), r.id);
    expect(db.sqlite.prepare("SELECT mode FROM scans WHERE id=?").get(r.id)).toMatchObject({ mode: "quick" });
    expect(await repo.cloneRecentScan(db, { userId: u2, url: "https://q.com/", host: "q.com", ipHash: null, mode: "full" })).toBeNull();
    const id = await repo.cloneRecentScan(db, { userId: u2, url: "https://q.com/", host: "q.com", ipHash: null, mode: "quick" });
    expect(db.sqlite.prepare("SELECT mode FROM scans WHERE id=?").get(id!)).toMatchObject({ mode: "quick" });
    const full = await completed(u1, "https://f.com/");
    const q = await repo.cloneRecentScan(db, { userId: u2, url: "https://f.com/", host: "f.com", ipHash: null, mode: "quick" });
    expect(q).toBeTruthy();
    expect(full).toBeTruthy();
  });
});

describe("tls cache", () => {
  it("lưu, đọc trong TTL, và hết hạn", async () => {
    await repo.putTlsCache(db, "a.com", { ok: true, n: 1 });
    expect(await repo.getTlsCache(db, "a.com")).toEqual({ ok: true, n: 1 });
    await repo.putTlsCache(db, "a.com", { ok: true, n: 2 });
    expect(await repo.getTlsCache(db, "a.com")).toEqual({ ok: true, n: 2 });
    db.sqlite.prepare("UPDATE tls_cache SET fetched_at=?").run(new Date(Date.now() - 13 * 3_600_000).toISOString());
    expect(await repo.getTlsCache(db, "a.com")).toBeNull();
  });
});
