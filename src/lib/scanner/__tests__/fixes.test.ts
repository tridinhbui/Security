import { describe, expect, it } from "vitest";
import { attachFixCommands, FIX_EXEMPT, FIXES } from "../fixes";
import { headerFix, httpsRedirectFix } from "../remediation";
import { ALL_RULES } from "../rules";
import { baseline, run } from "./fixtures";
import { makeFinding } from "../util";
import type { Finding } from "../types";

const fail = (ruleId: string, extra: Partial<Parameters<typeof makeFinding>[0]> = {}): Finding =>
  makeFinding({ ruleId, title: "t", category: "Headers", severity: "medium", confidence: "high", status: "fail", summary: "s", explanation: "e", ...extra });

describe("thư viện lệnh khắc phục", () => {
  it("MỌI luật phải có lệnh khắc phục hoặc nằm trong danh sách miễn trừ có chủ đích", () => {
    const missing = ALL_RULES.map((r) => r.id).filter((id) => !(id in FIXES) && !FIX_EXEMPT.has(id));
    expect(missing).toEqual([]);
    for (const id of Object.keys(FIXES)) expect(ALL_RULES.some((r) => r.id === id), `${id} không còn tồn tại`).toBe(true);
  });

  it("mỗi luật có lệnh đều sinh ra snippet có nhãn, ngôn ngữ và nội dung", () => {
    for (const [id, fn] of Object.entries(FIXES)) {
      const out = fn({ host: "example.com", platforms: [], finding: fail(id), now: new Date("2026-10-05T00:00:00Z") });
      expect(out.length, id).toBeGreaterThan(0);
      for (const s of out) { expect(s.label, id).toBeTruthy(); expect(s.language, id).toBeTruthy(); expect(s.code.trim().length, id).toBeGreaterThan(5); }
    }
  });

  it("không có lệnh phá huỷ nào trong thư viện", () => {
    const all = Object.entries(FIXES).flatMap(([id, fn]) => fn({ host: "example.com", platforms: ["nginx", "apache", "express", "nextjs", "cloudflare", "vercel"], finding: fail(id), now: new Date() }).map((s) => `${id}: ${s.code}`));
    for (const line of all) {
      expect(line).not.toMatch(/\brm\s+-|\bsed\s+-i|\bmkfs|\bdd\s+if=|>\s*\/etc\/|chmod\s+-R\s+777|curl[^|\n]*\|\s*(ba)?sh|\bsudo\s+rm\b|git\s+(push\s+--force|reset\s+--hard)/);
    }
  });

  it("gắn lệnh vào phát hiện lỗi, giữ nguyên fingerprint, không động tới phát hiện đạt", () => {
    const f = fail("tls.hsts", { key: "k" });
    const pass = { ...fail("tls.hsts"), status: "pass" as const };
    const [a, b] = attachFixCommands([f, pass], { host: "example.com", platforms: [] });
    expect(a!.fingerprint).toBe(f.fingerprint);
    expect(a!.remediation!.snippets.some((s) => s.language === "bash" && s.code.includes("curl -sI https://example.com/"))).toBe(true);
    expect(b).toBe(pass);
  });

  it("không trùng nhãn khi áp dụng hai lần, và giữ snippet có sẵn của luật", () => {
    const f = { ...fail("headers.x-content-type-options"), remediation: headerFix("X-Content-Type-Options", "nosniff", ["nginx"]) };
    const once = attachFixCommands([f], { host: "example.com", platforms: ["nginx"] })[0]!;
    const twice = attachFixCommands([once], { host: "example.com", platforms: ["nginx"] })[0]!;
    expect(twice.remediation!.snippets.map((s) => s.label)).toEqual(once.remediation!.snippets.map((s) => s.label));
    expect(once.remediation!.snippets.some((s) => s.platform === "nginx")).toBe(true);
  });

  it("host không an toàn cho shell thì KHÔNG chèn vào lệnh", () => {
    for (const host of ["a.com; rm -rf /", "$(id).com", "a b.com", "a.com`x`"]) {
      const f = fail("tls.hsts");
      expect(attachFixCommands([f], { host, platforms: [] })[0]).toBe(f);
    }
  });

  it("security.txt có ngày hết hạn sau 1 năm", () => {
    const [f] = attachFixCommands([fail("exposure.security-txt")], { host: "www.example.com", platforms: [], now: new Date("2026-10-05T12:00:00Z") });
    const code = f!.remediation!.snippets.map((s) => s.code).join("\n");
    expect(code).toContain("Expires: 2027-10-05T12:00:00Z");
    expect(code).toContain("mailto:security@example.com");
  });

  it("chưa nhận diện nền tảng → liệt kê các lựa chọn có nhãn thay vì chỉ một dòng header", () => {
    const h = headerFix("X-Frame-Options", "DENY", []);
    expect(h.platformUnknown).toBe(true);
    expect(new Set(h.snippets.map((s) => s.platform))).toEqual(new Set(["generic", "nextjs", "vercel", "cloudflare", "nginx", "apache", "express"]));
    expect(httpsRedirectFix([]).snippets.length).toBeGreaterThan(3);
  });

  it("end-to-end: quét baseline lỗi → mọi phát hiện lỗi có lệnh khắc phục", () => {
    const obs = baseline();
    obs.https!.headers = {};
    const findings = attachFixCommands(run(obs), { host: "example.com", platforms: obs.platforms });
    const failing = findings.filter((f) => f.status === "fail");
    expect(failing.length).toBeGreaterThan(3);
    for (const f of failing) if (!FIX_EXEMPT.has(f.ruleId)) expect(f.remediation?.snippets.length, f.ruleId).toBeGreaterThan(0);
  });
});
