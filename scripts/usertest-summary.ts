import { readFileSync } from "node:fs";
import { parseCsv, summarize } from "../src/lib/usertest-summary";

const file = process.argv[2];
if (!file) { console.error("Cách dùng: npx tsx scripts/usertest-summary.ts docs/user-testing/observations.csv"); process.exit(2); }
const s = summarize(parseCsv(readFileSync(file, "utf8")));
const f = (n: number | null, d = 1) => (n === null ? "—" : n.toFixed(d));
console.log(`Người tham gia: ${s.participants} (${Object.entries(s.groups).map(([g, n]) => `${g}:${n}`).join(", ") || "chưa có"})`);
console.log("\nNhiệm vụ         hoàn thành   trung vị (giây)   hiểu TB (0–2)");
for (const t of s.tasks) console.log(`${t.task.padEnd(16)} ${`${t.completed}/${t.n}`.padEnd(12)} ${f(t.medianSeconds, 0).padEnd(17)} ${f(t.meanUnderstanding)}`);
console.log("\nPhát hiện (xếp theo mức cần sửa)");
for (const r of s.rules) console.log(`${r.flag.padEnd(13)} ${r.rule.padEnd(34)} n=${r.n} hiểu=${f(r.meanUnderstanding)} chưa-rõ=${r.unclearVotes} sai-người=${r.wrongOwner} không-thấy-cách-sửa=${r.fixNotFound}${r.notes.length ? `\n              ghi chú: ${r.notes.join(" | ")}` : ""}`);
if (s.invalid.length) console.log(`\nDòng không hợp lệ (bị bỏ qua):\n- ${s.invalid.join("\n- ")}`);
console.log(`\nGiới hạn:\n- ${s.caveats.join("\n- ")}`);
