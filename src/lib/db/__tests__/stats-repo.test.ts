import { describe, expect, it } from "vitest";
import { bumpCounter, publicStats } from "../stats-repo";
import { createTestD1 } from "./test-d1";

describe("số liệu công khai trên trang chủ (chỉ số thật)", () => {
  it("đếm đúng số tài khoản và số lượt quét; mỗi lượt quét cộng đúng 1", async () => {
    const db = createTestD1();
    db.sqlite.exec("DELETE FROM site_counters WHERE name LIKE 'baseline_%'"); // test số đếm thuần; mốc lịch sử có test riêng bên dưới
    const base = await publicStats(db);
    db.sqlite.prepare("INSERT INTO users (id,email,password_hash,created_at) VALUES ('u1','a@x.vn','x',datetime('now')), ('u2','b@x.vn','x',datetime('now'))").run();
    await bumpCounter(db, "scans"); await bumpCounter(db, "scans"); await bumpCounter(db, "scans");
    expect(await publicStats(db)).toEqual({ scans: base.scans + 3, users: base.users + 2 });
  });
  it("chưa chạy migration bộ đếm: lượt quét không bị hỏng, số liệu quay về số lượt quét đã lưu", async () => {
    const db = createTestD1();
    db.sqlite.exec("DROP TABLE site_counters");
    await expect(bumpCounter(db, "scans")).resolves.toBeUndefined();
    expect((await publicStats(db)).scans).toBe(0);
  });
});

describe("mốc lịch sử (số thật đã mất khỏi CSDL)", () => {
  it("cộng mốc vào số đếm hiện tại; sửa mốc trong CSDL là đổi ngay, không cần deploy", async () => {
    const db = createTestD1();
    db.sqlite.exec("UPDATE site_counters SET value = 0 WHERE name = 'scans'");
    const before = await publicStats(db);
    expect(db.sqlite.prepare("SELECT value FROM site_counters WHERE name='baseline_scans'").get()).toEqual({ value: 1000 });
    expect(db.sqlite.prepare("SELECT value FROM site_counters WHERE name='baseline_users'").get()).toEqual({ value: 300 });
    await bumpCounter(db, "scans");
    expect((await publicStats(db)).scans).toBe(before.scans + 1);
    expect(before.scans).toBe(1000);
    db.sqlite.exec("UPDATE site_counters SET value = 500 WHERE name = 'baseline_scans'");
    expect((await publicStats(db)).scans).toBe(501);
  });
  it("mốc âm hoặc thiếu bảng không làm hỏng trang chủ", async () => {
    const db = createTestD1();
    db.sqlite.exec("UPDATE site_counters SET value = -5 WHERE name LIKE 'baseline_%'");
    expect((await publicStats(db)).users).toBeGreaterThanOrEqual(0);
  });
});
