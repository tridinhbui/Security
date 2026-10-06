import { describe, expect, it } from "vitest";
import { ANALYST, ORIGINS, originFor, reproFor } from "../analyst";
import { QUICK_RULES, toItems } from "../quick";
import { attachFixCommands } from "../fixes";
import { makeFinding } from "../util";
import { ALL_RULES } from "../rules";

/** Luật chỉ mang tính thông tin, không bao giờ báo lỗi. */
const INFO_ONLY = new Set(["config.technology", "config.auth-surface"]);

describe("góc nhìn analyst", () => {
  it("mọi luật trong quét nhanh có câu khẳng định + câu phụ (không phải câu hỏi) và nguồn gốc hợp lệ", () => {
    for (const id of Object.keys(QUICK_RULES).concat(ALL_RULES.map((r) => r.id).filter((x) => !INFO_ONLY.has(x)))) {
      const e = ANALYST[id];
      expect(e, `${id} thiếu câu khẳng định`).toBeTruthy();
      expect(e!.statement.endsWith("?"), `${id}: phải là câu khẳng định`).toBe(false);
      expect(e!.sub.endsWith("?")).toBe(false);
      expect(e!.statement.length).toBeGreaterThan(12);
      expect(ORIGINS[e!.origin]).toBeTruthy();
    }
  });
  it("ví dụ chuẩn: chuyển hướng HTTP→HTTPS", () => {
    expect(ANALYST["tls.http-to-https-redirect"]).toMatchObject({ statement: "Khách hàng chưa được đưa sang phiên bản an toàn", sub: "Khách hàng vẫn có thể truy cập trang web bằng đường dẫn không có bảo mật", origin: "absent" });
  });
  it("phân biệt “chưa hề nghĩ tới” với “đã nghĩ tới nhưng làm sai” / “bỏ sót bảo trì”", () => {
    expect(originFor("headers.csp", "Thiếu Content-Security-Policy").kind).toBe("absent");
    expect(originFor("headers.csp", "Content-Security-Policy còn yếu").kind).toBe("misconfigured");
    expect(originFor("tls.hsts", "Thiếu header HSTS").kind).toBe("absent");
    expect(originFor("tls.hsts", "Thời hạn HSTS quá ngắn").kind).toBe("misconfigured");
    expect(originFor("config.dns-email-security", "Chưa có bản ghi DMARC").kind).toBe("absent");
    expect(originFor("config.dns-email-security", "DMARC chỉ ở chế độ giám sát (p=none)").kind).toBe("misconfigured");
    expect(originFor("exposure.security-txt", "security.txt đã hết hạn").kind).toBe("lapse");
    expect(originFor("tls.certificate-expiry", "Chứng chỉ sắp hết hạn").kind).toBe("lapse");
    expect(originFor("exposure.secrets", "Khoá bí mật").kind).toBe("exposure");
    expect(originFor("headers.broken", "X-Frame-Options không hợp lệ").kind).toBe("misconfigured");
    for (const k of Object.keys(ORIGINS)) expect(ORIGINS[k as keyof typeof ORIGINS].rootCause.length).toBeGreaterThan(10);
  });
  it("lệnh tái hiện chỉ đọc, chèn host an toàn; host lạ → null", () => {
    for (const id of ALL_RULES.map((r) => r.id).filter((x) => !INFO_ONLY.has(x))) {
      const c = reproFor(id, "example.com");
      expect(c, id).toBeTruthy();
      expect(c).not.toMatch(/\brm\b|\bsed\s+-i|\bsudo\b|>\s*\/(?!dev\/null)|\|\s*(ba)?sh\b|-X\s+(POST|PUT|DELETE)/);
    }
    for (const h of ["a.com; rm -rf /", "$(id).com", "a b.com", "a.com`x`"]) expect(reproFor("tls.hsts", h)).toBeNull();
  });
  it("mục chưa đạt có statement/origin/repro; mục đạt thì không", () => {
    const base = { category: "Headers" as const, confidence: "high" as const, summary: "s", explanation: "e" };
    const bad = makeFinding({ ruleId: "tls.http-to-https-redirect", title: "HTTP không chuyển hướng", severity: "medium", status: "fail", ...base });
    const ok = makeFinding({ ruleId: "tls.hsts", title: "HSTS ổn", severity: "info", status: "pass", ...base });
    const items = toItems(attachFixCommands([bad, ok], { host: "example.com", platforms: [] }), "example.com");
    const f = items.find((i) => i.status === "fail")!, p = items.find((i) => i.status === "pass")!;
    expect(f.tech).toMatchObject({ statement: "Khách hàng chưa được đưa sang phiên bản an toàn", origin: { kind: "absent" } });
    expect(f.tech!.repro).toContain("curl -sIL http://example.com/");
    expect(p.tech!.statement).toBeUndefined();
    expect(p.tech!.repro).toBeUndefined();
  });
});

import { toMarkdown } from "@/lib/guidance";
describe("báo cáo Markdown có góc nhìn analyst", () => {
  it("chứa câu khẳng định, nguồn gốc, hậu quả và lệnh tái hiện", () => {
    const f = makeFinding({ ruleId: "tls.http-to-https-redirect", title: "HTTP không chuyển hướng", category: "Transport Security", severity: "medium", confidence: "high", status: "fail", summary: "s", explanation: "e" });
    const md = toMarkdown({ url: "https://example.com/", host: "example.com", scannedAt: "2026-01-01", score: 60, grade: "D", findings: [f], categoryScores: {}, disclaimer: "d" });
    expect(md).toContain("Khách hàng chưa được đưa sang phiên bản an toàn");
    expect(md).toContain("Chưa triển khai");
    expect(md).toContain("Trong 1 ngày:");
    expect(md).toContain("curl -sIL http://example.com/");
  });
});
