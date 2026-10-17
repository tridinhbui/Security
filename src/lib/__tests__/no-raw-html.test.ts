import { readdirSync, readFileSync, statSync } from "node:fs";
import { join } from "node:path";
import { describe, expect, it } from "vitest";

const walk = (d: string): string[] => readdirSync(d).flatMap((n) => { const p = join(d, n); return statSync(p).isDirectory() ? (n === "__tests__" ? [] : walk(p)) : /\.tsx$/.test(n) ? [p] : []; });

describe("chống XSS qua nhận xét tự do và giải thích", () => {
  it("không component/trang nào dùng dangerouslySetInnerHTML (React luôn escape văn bản)", () => {
    const bad = [...walk("src/components"), ...walk("src/app")].filter((f) => /dangerouslySetInnerHTML/.test(readFileSync(f, "utf8")));
    expect(bad).toEqual([]);
  });
  it("trang quản trị chỉ hiển thị nhận xét dưới dạng văn bản và bắt buộc quyền admin", () => {
    const src = readFileSync("src/app/(app)/admin/giai-thich/page.tsx", "utf8");
    expect(src).toMatch(/if \(!\(await getAdmin\(\)\)\) notFound\(\)/);
    expect(src).toContain("{c.comment}");
  });
});
