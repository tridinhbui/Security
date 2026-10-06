import { describe, expect, it } from "vitest";
import { createTestD1, seedUser } from "@/lib/db/__tests__/test-d1";
import { adminListHelp, adminUpdateHelp, cancelMyHelp, countRecentHelp, createHelpRequest, listMyHelp } from "@/lib/db/help-repo";
import { insertProjectScan } from "@/lib/db/project-repo";
import { loadHelpSource, toHelpIssue } from "../help";
import { item } from "../types";

describe("help requests", () => {
  it("cách ly theo người dùng, huỷ, báo giá, giới hạn", async () => {
    const db = createTestD1();
    const a = await seedUser(db, "a@x.com"), b = await seedUser(db, "b@x.com");
    const items = [item({ id: "x", group: "g", source: "code", title: "Lộ khoá", severity: "critical", status: "fail", summary: "s", why: "w", evidence: ["a.ts:1 — sk_l…(32 ký tự)", "b", "c", "d"] }), item({ id: "y", group: "g", source: "code", title: "ok", severity: "info", status: "pass", summary: "s", why: "w" })];
    const sid = await insertProjectScan(db, { userId: a, kind: "code", label: "o/r", score: 50, grade: "F", counts: {}, items, retentionDays: 30 });
    expect(await loadHelpSource(db, b, "code", sid)).toBeNull(); // không đọc được báo cáo của người khác
    const src = (await loadHelpSource(db, a, "code", sid))!;
    expect(src.items).toHaveLength(1); // chỉ lấy mục lỗi
    expect(toHelpIssue(src.items[0]!).evidence).toHaveLength(3);
    const id = await createHelpRequest(db, { userId: a, kind: "code", sourceId: sid, label: src.label, issues: src.items.map(toHelpIssue), note: "gấp", contact: "a@x.com" });
    expect(await countRecentHelp(db, a, 86_400_000)).toBe(1);
    expect(await listMyHelp(db, b)).toHaveLength(0);
    expect(await adminUpdateHelp(db, id, "quoted", "Báo giá 2tr")).toBe(true);
    expect((await adminListHelp(db))[0]).toMatchObject({ status: "quoted", quote: "Báo giá 2tr", email: "a@x.com" });
    expect(await cancelMyHelp(db, b, id)).toBe(false);
    expect(await cancelMyHelp(db, a, id)).toBe(true);
    expect(await adminUpdateHelp(db, id, "done", "")).toBe(false); // đã huỷ thì không đổi
  });
});
