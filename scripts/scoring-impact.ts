/* Định lượng tác động của việc đổi mức nghiêm trọng lên điểm số (chỉ đọc, không đổi mã sản phẩm).
 * Chạy: npx tsx scripts/scoring-impact.ts */
import { calculateScore, gradeFor, penalty, PASSIVE_SCORE_CEILING } from "../src/lib/scanner/score";
import { demoReport } from "../src/lib/demo";
import { OWASP_MAP } from "../src/lib/guidance";
import type { Finding, Severity } from "../src/lib/scanner/types";

const pen = (sev: Severity, conf: Finding["confidence"]) => penalty({ status: "fail", severity: sev, confidence: conf });
console.log("## Phạt điểm từng phát hiện (trừ trực tiếp vào điểm tổng; nhóm bị trừ ×1.5)");
for (const [id, cur, prop, conf] of [["exposure.source-maps", "medium", "low", "high"], ["adv.dom-xss-flow", "medium", "low", "low"]] as const) {
  console.log(`${id}: ${cur}×${conf}=${pen(cur, conf)} → ${prop}×${conf}=${pen(prop, conf)} | điểm tổng +${(pen(cur, conf) - pen(prop, conf)).toFixed(1)} | điểm nhóm +${((pen(cur, conf) - pen(prop, conf)) * 1.5).toFixed(1)}`);
}

console.log("\n## Báo cáo demo (website mẫu)");
const d = demoReport();
const mutate = (sev: Record<string, Severity>) => d.findings.map((f) => (sev[f.ruleId] && f.status === "fail" ? { ...f, severity: sev[f.ruleId]! } : f));
const lim = (fs: Finding[]) => calculateScore(fs, { limitedCoverage: false });
const cur = lim(d.findings), prop = lim(mutate({ "exposure.source-maps": "low", "adv.dom-xss-flow": "low" }));
console.log(`hiện tại ${cur.score} (${cur.grade}) → đề xuất ${prop.score} (${prop.grade}); có source-maps: ${d.findings.some((f) => f.ruleId === "exposure.source-maps" && f.status === "fail")}; có dom-xss: ${d.findings.some((f) => f.ruleId === "adv.dom-xss-flow" && f.status === "fail")}`);

console.log("\n## Xác suất đổi hạng chữ cái (giả định điểm gốc phân bố đều 0..96; tính theo từng mức tăng điểm)");
for (const delta of [4, 1.6, 5.6]) {
  let flips = 0, n = 0;
  for (let s = 0; s <= PASSIVE_SCORE_CEILING; s++) { n++; if (gradeFor(s) !== gradeFor(Math.min(PASSIVE_SCORE_CEILING, Math.round(s + delta)))) flips++; }
  console.log(`+${delta} điểm: ${flips}/${n} điểm gốc (${((100 * flips) / n).toFixed(0)}%) đổi hạng`);
}
console.log("(site sạch: trần 96 hấp thụ một phần; vd. 100−7=93 → +4 = 97 → 96)");

console.log("\n## Số luật theo hạng mục OWASP_MAP hiện tại (2021)");
const cnt: Record<string, number> = {};
for (const v of Object.values(OWASP_MAP)) for (const c of v) { const k = c.split(" ")[0]!; cnt[k] = (cnt[k] ?? 0) + 1; }
console.log(Object.entries(cnt).sort().map(([k, v]) => `${k}:${v}`).join("  "), "| tổng luật có ánh xạ:", Object.keys(OWASP_MAP).length);
