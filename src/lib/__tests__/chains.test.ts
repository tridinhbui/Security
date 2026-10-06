import { describe, expect, it } from "vitest";
import { attackChains } from "../chains";
import { asvsPosture } from "../standards";
import type { Finding } from "../scanner/types";

const f = (ruleId: string, status: Finding["status"] = "fail", severity: Finding["severity"] = "medium"): Finding => ({
  ruleId, title: ruleId, category: "Headers", severity, confidence: "high", status, summary: "s", explanation: "e", evidence: [], remediation: null, affectedUrl: null, references: [], fingerprint: `${ruleId}|${status}`,
});

describe("chuỗi tấn công", () => {
  it("không có chuỗi khi chỉ có một mắt xích hoặc mọi thứ đều đạt", () => {
    expect(attackChains([f("headers.csp")])).toEqual([]);
    expect(attackChains([f("headers.csp", "pass"), f("adv.dom-xss-flow", "pass")])).toEqual([]);
  });
  it("CSP yếu + vector chèn mã tạo chuỗi XSS; thêm cookie lộ thì hoàn chỉnh và nâng một bậc", () => {
    const base = attackChains([f("adv.csp-analysis", "fail", "low"), f("adv.dom-xss-flow", "fail", "medium")]);
    expect(base.map((c) => c.id)).toEqual(["xss-session"]);
    expect(base[0]!.complete).toBe(false);
    expect(base[0]!.severity).toBe("medium");
    const full = attackChains([f("adv.csp-analysis", "fail", "low"), f("adv.dom-xss-flow", "fail", "medium"), f("cookies.flags", "fail", "low")]);
    expect(full[0]!.complete).toBe(true);
    expect(full[0]!.severity).toBe("high");
  });
  it("không nâng quá High và không tự thành Critical", () => {
    const c = attackChains([f("headers.csp", "fail", "high"), f("adv.supply-chain", "fail", "high"), f("cookies.flags", "fail", "high")]);
    expect(c.every((x) => x.severity !== "critical")).toBe(true);
  });
  it("sắp theo mức nghiêm trọng giảm dần và có cách cắt chuỗi", () => {
    const cs = attackChains([f("tls.hsts", "fail", "medium"), f("tls.http-to-https-redirect", "fail", "medium"), f("adv.dmarc-deep", "fail", "low")]);
    expect(cs.map((c) => c.id)).toEqual(["downgrade", "mail-spoof"]);
    for (const c of cs) { expect(c.cut.length).toBeGreaterThan(10); expect(c.steps).toHaveLength(3); }
  });
  it("ghi chú (status info) của bản đồ endpoint vẫn là mắt xích", () => {
    const cs = attackChains([f("exposure.source-maps"), f("config.server-disclosure"), f("adv.endpoint-map", "info", "info")]);
    expect(cs.find((c) => c.id === "recon")?.complete).toBe(true);
  });
});

describe("tư thế ASVS", () => {
  it("gom theo chương và đếm theo luật", () => {
    const rows = asvsPosture([f("tls.hsts", "fail"), f("tls.cipher-suite", "pass"), f("cookies.flags", "fail")]);
    expect(rows.map((r) => r.chapter)).toEqual(["3", "9", "14"]);
    expect(rows.find((r) => r.chapter === "14")).toMatchObject({ failing: 1, reqs: ["14.4.5"] });
    expect(rows.find((r) => r.chapter === "3")!.reqs).toEqual(["3.4.1", "3.4.2", "3.4.3"]);
  });
});
