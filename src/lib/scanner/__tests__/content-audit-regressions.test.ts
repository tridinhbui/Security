import { readFileSync } from "node:fs";
import { describe, expect, it } from "vitest";

/**
 * Hồi quy cho các lỗi nội dung do audit độc lập (Phase 3.4) tìm ra và đã được kiểm chứng.
 * Kiểm theo mã nguồn vì đây là các chuỗi văn bản/lệnh; mục đích là không để quay lại lỗi cũ.
 */
const src = (f: string) => readFileSync(`src/lib/scanner/${f}`, "utf8");

describe("audit nội dung — các lỗi đã sửa không quay lại", () => {
  it("Referrer-Policy: không khẳng định trình duyệt hiện đại gửi địa chỉ đầy đủ khi thiếu header", () => {
    expect(src("explain.ts")).not.toContain("trình duyệt gửi địa chỉ đầy đủ của trang hiện tại cho website kế tiếp");
    expect(src("explain.ts")).toContain("strict-origin-when-cross-origin");
    expect(src("impact.ts")).not.toContain("địa chỉ trang hiện tại (kể cả tham số) có thể gửi cho website kia");
  });
  it("lệnh kiểm tra TLS cũ không còn coi “Cipher is (NONE)” là chấp nhận, và phân biệt “máy bạn không hỗ trợ”", () => {
    for (const f of ["analyst.ts", "explain-more.ts"]) {
      const s = src(f);
      expect(s).not.toContain('grep -qE "BEGIN CERT|Cipher is"');
      expect(s).toContain("no protocols available");
    }
    // regex mới: khớp cipher thật, không khớp "(NONE)" hay "0000" của lần bắt tay thất bại
    const re = /(Cipher *: *|Cipher is )[A-Z][A-Z0-9_-]{3,}/;
    expect(re.test("    Cipher    : TLS_AES_256_GCM_SHA384")).toBe(true);
    expect(re.test("New, (NONE), Cipher is (NONE)")).toBe(false);
    expect(re.test("    Cipher    : 0000")).toBe(false);
    expect(re.test("New, TLSv1.3, Cipher is TLS_AES_256_GCM_SHA384")).toBe(true);
  });
  it("DMARC: lộ trình bắt đầu ở p=none, không dán sẵn quarantine + căn chỉnh nghiêm ngặt", () => {
    const s = src("fixes.ts");
    expect(s).not.toContain("p=quarantine; pct=100; rua=mailto:dmarc@${d}; adkim=s; aspf=s");
    expect(s).toContain('"v=DMARC1; p=none; rua=mailto:dmarc@${d}"');
  });
  it("SPF: chú thích không nằm trong dòng giá trị TXT", () => {
    expect(src("fixes.ts")).not.toContain("~all   # ví dụ Google Workspace");
  });
  it("CSP chính thức có cảnh báo trước khi dán, và Report-Only nói rõ cần nơi nhận báo cáo", () => {
    const s = src("fixes.ts");
    expect(s).toContain("CHỈ bật bản chính thức dưới đây sau khi Report-Only không còn vi phạm");
    expect(s).toContain("report-to/report-uri");
  });
  it("hạn chứng chỉ: không còn nói “60–90 ngày” là chuẩn; nêu mức 200 ngày từ 15/03/2026", () => {
    const s = src("explain-more.ts");
    expect(s).not.toContain("khoảng 60–90 ngày");
    expect(s).toContain("200 ngày");
  });
  it("sitemap.xml: là thông tin SEO, không phải “lộ đường dẫn”; GraphQL/DOM-XSS/postMessage nêu rõ độ tin cậy thấp", () => {
    const a = src("analyst.ts"), i = src("impact.ts");
    expect(a).not.toContain("Sơ đồ website liệt kê đường dẫn không định công khai");
    expect(i).not.toContain('worst: "Liệt kê đường dẫn không định công khai."');
    expect(a).not.toContain("GraphQL cho phép xem toàn bộ cấu trúc dữ liệu");
    expect(a).toContain("độ tin cậy thấp");
  });
});
