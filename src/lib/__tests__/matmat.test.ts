import { describe, expect, it } from "vitest";
import { buildAllPrompt, buildFixPrompt } from "../ai-prompt";
import { FEYNMAN } from "../feynman";
import { reply, type BotContext } from "../matmat";
import { ALL_RULES } from "../scanner/rules";
import type { Finding } from "../scanner/types";

const f = (ruleId: string, severity: Finding["severity"] = "high"): Finding => ({
  ruleId, title: `Tiêu đề ${ruleId}`, category: "Headers", severity, confidence: "high", status: "fail",
  summary: "Thiếu header", explanation: "Kẻ xấu lợi dụng", evidence: ["x-frame-options: (none)"],
  remediation: { summary: "Thêm header", steps: ["Mở cấu hình"], snippets: [{ platform: "nginx", language: "nginx", label: "nginx", code: "add_header X-Frame-Options DENY;" }] },
  affectedUrl: "https://a.com/", references: [], fingerprint: ruleId,
});
const ctx: BotContext = { host: "a.com", score: 55, grade: "D", platforms: ["nginx"], issues: [f("headers.frame-protection"), f("tls.hsts", "medium")] };

describe("Feynman", () => {
  it("mọi luật đều có giải thích đơn giản", () => {
    const missing = ALL_RULES.map((r) => r.id).filter((id) => !FEYNMAN[id]);
    expect(missing).toEqual([]);
  });
});

describe("prompt cho AI", () => {
  it("chứa vấn đề, hệ thống, đoạn cấu hình và yêu cầu kiểm tra lại", () => {
    const p = buildFixPrompt(f("headers.frame-protection"), "a.com", ["nginx"]);
    for (const x of ["a.com", "nginx", "add_header X-Frame-Options DENY;", "Yêu cầu", "curl -sI https://a.com"]) expect(p).toContain(x);
  });
  it("prompt gộp xếp theo mức nghiêm trọng", () => {
    const p = buildAllPrompt([f("tls.hsts", "low"), f("headers.csp", "critical")], "a.com");
    expect(p.indexOf("[critical]")).toBeLessThan(p.indexOf("[low]"));
  });
});

describe("Mật Mật", () => {
  it("giải thích thuật ngữ", () => expect(reply("HSTS là gì", null).text).toContain("kết nối an toàn"));
  it("xin prompt thì trả về nút copy", () => expect(reply("cho mình prompt để AI sửa", ctx).copy?.text).toContain("a.com"));
  it("nên sửa gì trước liệt kê việc cần làm", () => expect(reply("Nên sửa gì trước?", ctx).text).toContain("1."));
  it("gặp người thật → chuyển sang hỗ trợ", () => expect(reply("cho mình gặp người thật", ctx).handoff).toBe(true));
  it("câu lạ có gợi ý thay vì im lặng", () => expect(reply("asdf qwer", ctx).chips.length).toBeGreaterThan(0));
  it("không có ngữ cảnh báo cáo thì không bịa dữ liệu", () => expect(reply("cho mình prompt", null).copy).toBeUndefined());
});
