import { describe, expect, it } from "vitest";
import { bumpCounter, publicStats } from "../stats-repo";
import { createTestD1 } from "./test-d1";

describe("số liệu công khai trên trang chủ (chỉ số thật)", () => {
  it("đếm đúng số tài khoản và số lượt quét; mỗi lượt quét cộng đúng 1", async () => {
    const db = createTestD1();
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
