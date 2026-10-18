import { beforeEach, describe, expect, it } from "vitest";
import { clarityByMode, cleanComment, cleanVariant, clarityByRule, clarityLevel, unclearLowerBound, recentUnclearComments, saveVote, VOTES_PER_HOUR } from "../explain-feedback";
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
    for (let i = 0; i < VOTES_PER_HOUR; i++) expect(await vote("spam", { ruleId: `r${i}`, variant: "v" })).toBe(true);
    expect(await vote("spam", { ruleId: "r-extra", variant: "extra" })).toBe(false);
    expect(await vote("khac", { variant: "extra" })).toBe(true);
  });
  it("lọc biến thể (không để lọt tên miền/URL) và cắt nhận xét", () => {
    expect(cleanVariant("xfo")).toBe("xfo");
    expect(cleanVariant("hsts-no-maxage")).toBe("hsts-no-maxage");
    for (const bad of ["/", "x:thu-ba.example.net", "https://a.com/x", "a b", "A", "", 5, null]) expect(cleanVariant(bad)).toBe("");
    expect(cleanComment("  nhiều   khoảng   trắng \n xuống dòng ")).toBe("nhiều khoảng trắng xuống dòng");
    expect(cleanComment("chữ ".repeat(500))).toHaveLength(300);
    expect(cleanComment("x".repeat(1000))).toBe("[đã ẩn]"); // chuỗi dài liền mạch giống token
    expect(cleanComment(undefined)).toBe("");
  });
});

describe("riêng tư của nhận xét tự do", () => {
  it.each([
    ["trang https://shop-cua-toi.vn/admin?token=abc bị lỗi", /shop-cua-toi|token=abc/],
    ["liên hệ tri@gmail.com giúp mình", /tri@gmail/],
    ["site của mình là khachhang.com.vn", /khachhang/],
    ["server 203.0.113.42 báo lỗi", /203\.0\.113/],
    ["khoá sk_live_51HabcdEFGhijkl của mình", /sk_live/],
    ["token ghp_abcdefghijklmnopqrstuvwxyz0123456789", /ghp_/],
    ["gọi 0912 345 678 nhé", /0912/],
    ["eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.abc", /eyJhbG/],
  ])("ẩn dữ liệu nhận dạng: %s", (input, leak) => {
    const out = cleanComment(input);
    expect(out).not.toMatch(leak);
    expect(out).toContain("[đã ẩn]");
  });
  it("giữ nguyên câu hỏi bình thường và bỏ ký tự điều khiển / đảo chiều chữ", () => {
    expect(cleanComment("Mình không hiểu “clickjacking” nghĩa là gì")).toBe("Mình không hiểu “clickjacking” nghĩa là gì");
    expect(cleanComment("a\u202eb\u0000c\u200bd")).toBe("a b c d");
    expect(cleanComment("<script>alert(1)</script>")).toBe("<script>alert(1)</script>"); // lưu dạng văn bản; giao diện luôn escape (xem test XSS)
  });
  it("nhận xét lưu trong DB đã được lọc khi đi qua đường lưu phiếu", async () => {
    await vote("a", { verdict: "unclear", comment: cleanComment("lỗi ở example.org và me@x.com") });
    const [c] = await recentUnclearComments(db);
    expect(c!.comment).not.toMatch(/example\.org|me@x/);
  });
});

describe("không kết luận từ mẫu nhỏ", () => {
  it("dưới 10 phiếu luôn là insufficient, kể cả khi 100% chưa rõ", () => {
    expect(clarityLevel(2, 2)).toBe("insufficient");
    expect(clarityLevel(9, 9)).toBe("insufficient");
  });
  it("đủ phiếu: ưu tiên chỉ khi cận dưới Wilson ≥ 30%", () => {
    expect(clarityLevel(10, 10)).toBe("priority");
    expect(clarityLevel(5, 10)).toBe("watch");     // 50% nhưng cận dưới ~24% → chưa chắc
    expect(clarityLevel(1, 20)).toBe("ok");
    expect(unclearLowerBound(5, 10)).toBeLessThan(0.3);
    expect(unclearLowerBound(0, 0)).toBe(0);
  });
});

describe("phân tích theo chế độ hiển thị (dữ liệu trong test chỉ để kiểm tra mã, không phải kết quả nghiên cứu)", () => {
  it("tách “dễ hiểu” và “kỹ thuật”; mỗi ô tự áp quy tắc mẫu nhỏ", async () => {
    for (let i = 0; i < 12; i++) await saveVote(db, { voter: `b${i}`, ruleId: "headers.csp", variant: "", verdict: i < 8 ? "unclear" : "clear", source: "quick", mode: "beginner", comment: "" });
    for (let i = 0; i < 3; i++) await saveVote(db, { voter: `t${i}`, ruleId: "headers.csp", variant: "", verdict: "unclear", source: "quick", mode: "technical", comment: "" });
    const r = await clarityByMode(db);
    const row = r.rules.find((x) => x.rule_id === "headers.csp")!;
    expect(row.beginner).toMatchObject({ clear: 4, unclear: 8, total: 12, level: "priority" });
    expect(row.technical).toMatchObject({ unclear: 3, total: 3, level: "insufficient" }); // 3/3 “chưa rõ” KHÔNG được coi là kết luận
    expect(r.overall.beginner.total).toBe(12);
    expect(r.overall.technical.level).toBe("insufficient");
  });
  it("không có phiếu nào → mọi ô là mẫu nhỏ, không bịa số", async () => {
    const r = await clarityByMode(db);
    expect(r.rules).toEqual([]);
    expect(r.overall.beginner).toMatchObject({ total: 0, level: "insufficient" });
  });
  it("2/2 phiếu “chưa rõ” không phải kết luận (mẫu nhỏ); 8/10 có cận dưới chắc chắn", async () => {
    expect(clarityLevel(2, 2)).toBe("insufficient");
    expect(clarityLevel(8, 10)).toBe("priority");
    expect(clarityLevel(1, 10)).toBe("ok");
  });
});
