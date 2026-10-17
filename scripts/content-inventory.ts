/* Sinh bảng kiểm kê nội dung của toàn bộ luật quét (dùng cho docs/SECURITY-CONTENT-AUDIT.md).
 * Chạy: npx tsx scripts/content-inventory.ts > /dev/stdout . Chỉ đọc, không gọi mạng. */
import { readFileSync, readdirSync } from "node:fs";
import { join } from "node:path";
import { ALL_RULES } from "../src/lib/scanner/rules";
import { STANDARDS } from "../src/lib/standards";
import { IMPACT } from "../src/lib/scanner/impact";
import { FIXES } from "../src/lib/scanner/fixes";
import { DEEP_DIVE } from "../src/lib/scanner/deep-dive";
import { FEYNMAN } from "../src/lib/feynman";
import { PLAIN_TITLES } from "../src/lib/beginner";

const dir = join(import.meta.dirname, "../src/lib/scanner/rules");
const src = readdirSync(dir).filter((f) => f.endsWith(".ts")).map((f) => readFileSync(join(dir, f), "utf8")).join("\n");
/** Các mức severity xuất hiện trong khối mã của từng luật (trích tĩnh, gần đúng). */
function sevs(id: string): string {
  const start = src.indexOf(`id: "${id}"`);
  if (start < 0) return "?";
  const next = src.slice(start + 10).search(/\n\s*id: "[a-z]+\.[a-z0-9-]+"/);
  const block = src.slice(start, next < 0 ? undefined : start + 10 + next);
  const set = new Set([...block.matchAll(/severity: "(critical|high|medium|low|info)"/g)].map((m) => m[1]!));
  const order = ["critical", "high", "medium", "low", "info"];
  return order.filter((o) => set.has(o)).join(", ") || "(động)";
}
console.log("| # | Luật | Nhóm | Mức nghiêm trọng (tĩnh) | CWE | ASVS | WSTG | Hình dung | Tác động | Fix theo nền tảng | Đào sâu |");
console.log("|---|---|---|---|---|---|---|---|---|---|---|");
ALL_RULES.forEach((r, i) => {
  const s = STANDARDS[r.id];
  const yes = (b: unknown) => (b ? "✓" : "—");
  console.log(`| ${i + 1} | \`${r.id}\` | ${r.category}${r.advanced ? " (nâng cao)" : ""} | ${sevs(r.id)} | ${s?.cwe.join(", ") || "—"} | ${s?.asvs.join(", ") || "—"} | ${s?.wstg.join(", ") || "—"} | ${yes(FEYNMAN[r.id] && PLAIN_TITLES[r.id])} | ${yes(IMPACT[r.id])} | ${yes(FIXES[r.id])} | ${yes(DEEP_DIVE[r.id])} |`);
});
