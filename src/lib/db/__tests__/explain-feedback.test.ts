import { beforeEach, describe, expect, it } from "vitest";
import { cleanComment, cleanVariant, clarityByRule, recentUnclearComments, saveVote, VOTES_PER_HOUR } from "../explain-feedback";
import { createTestD1 } from "./test-d1";

let db: ReturnType<typeof createTestD1>;
beforeEach(() => { db = createTestD1(); });
const vote = (voter: string, o: Partial<Parameters<typeof saveVote>[1]> = {}) =>
  saveVote(db, { voter, ruleId: "headers.csp", variant: "", verdict: "clear", source: "quick", mode: "beginner", comment: "", ...o });

describe("phiếu “giải thích có rõ không?”", () => {
  it("tổng hợp theo luật; mục nhiều phiếu “chưa” đứng đầu", async () => {
    await vote("a", { verdict: "unclear", ruleId: "headers.broken", variant: "xfo", comment: "không hiểu ALLOW-FROM" });
    await vote("b", { verdict: "unclear", ruleId: "headers.broken", variant: "xfo" });
    await vote("c", { verdict: "clear", ruleId: "headers.broken", variant: "xfo" });
    await vote("a", { verdict: "clear", ruleId: "tls.hsts" });
    const rows = await clarityByRule(db);
    expect(rows[0]).toMatchObject({ rule_id: "headers.broken", variant: "xfo", clear: 1, unclear: 2, total: 3 });
    expect(rows.find((r) => r.rule_id === "tls.hsts")).toMatchObject({ clear: 1, unclear: 0 });
  });
  it("mỗi người một phiếu cho mỗi (luật, biến thể): bình chọn lại là ĐỔI phiếu, không nhân đôi", async () => {
    await vote("a", { verdict: "clear" });
    await vote("a", { verdict: "unclear", comment: "chưa rõ" });
    const rows = await clarityByRule(db);
    expect(rows).toHaveLength(1);
    expect(rows[0]).toMatchObject({ clear: 0, unclear: 1, total: 1 });
  });
  it("nhận xét chỉ được lưu khi chọn “chưa rõ”", async () => {
    await vote("a", { verdict: "clear", comment: "không nên lưu" });
    await vote("b", { verdict: "unclear", comment: "chỗ này khó hiểu" });
    const c = await recentUnclearComments(db);
    expect(c.map((x) => x.comment)).toEqual(["chỗ này khó hiểu"]);
  });
  it("giới hạn tốc độ theo người bình chọn", async () => {
    for (let i = 0; i < VOTES_PER_HOUR; i++) expect(await vote("spam", { variant: `v${i}` })).toBe(true);
    expect(await vote("spam", { variant: "extra" })).toBe(false);
    expect(await vote("khac", { variant: "extra" })).toBe(true);
  });
  it("lọc biến thể (không để lọt tên miền/URL) và cắt nhận xét", () => {
    expect(cleanVariant("xfo")).toBe("xfo");
    expect(cleanVariant("hsts-no-maxage")).toBe("hsts-no-maxage");
    for (const bad of ["/", "x:thu-ba.example.net", "https://a.com/x", "a b", "A", "", 5, null]) expect(cleanVariant(bad)).toBe("");
    expect(cleanComment("  nhiều   khoảng   trắng \n xuống dòng ")).toBe("nhiều khoảng trắng xuống dòng");
    expect(cleanComment("x".repeat(1000))).toHaveLength(300);
    expect(cleanComment(undefined)).toBe("");
  });
});
