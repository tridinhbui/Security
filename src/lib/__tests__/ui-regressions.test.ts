import { readFileSync } from "node:fs";
import { describe, expect, it } from "vitest";

/**
 * Hồi quy giao diện bằng kiểm tra mã nguồn (không cần trình duyệt).
 * Lỗi đã gặp: textarea của chatbot dùng `!h-auto` (important) nên chiều cao do JS gán bị đè, ô không bao giờ tự giãn.
 */
describe("chatbot: ô nhập nhiều dòng", () => {
  const src = readFileSync("src/components/matmat/MatMat.tsx", "utf8");
  const ta = /<textarea[\s\S]*?\/>/.exec(src)?.[0] ?? "";
  it("là textarea, tối đa 2000 ký tự, Enter gửi / Shift+Enter xuống dòng", () => {
    expect(ta).toContain("maxLength={MAX_LEN}");
    expect(src).toContain("const MAX_LEN = 2000");
    expect(ta).toMatch(/e\.key === "Enter" && !e\.shiftKey/);
    expect(ta).toContain("isComposing"); // không gửi nhầm khi đang gõ tiếng Việt bằng bộ gõ (Telex/VNI)
  });
  it("KHÔNG dùng lớp chiều cao `!important` (làm hỏng việc tự giãn theo nội dung)", () => {
    expect(ta).not.toMatch(/!h-/);
    expect(ta).toMatch(/max-h-/); // có trần để không che hết hộp thoại
  });
  it("hiệu ứng tự giãn tồn tại và có trần", () => {
    expect(src).toMatch(/el\.style\.height = "auto"/);
    expect(src).toMatch(/Math\.min\(el\.scrollHeight, 168\)/);
  });
});

describe("bình chọn độ rõ: vùng chạm trên điện thoại", () => {
  const src = readFileSync("src/components/ClarityVote.tsx", "utf8");
  it("nút cao 40px trên điện thoại (mục tiêu chạm), 32px từ màn hình sm trở lên", () => {
    const sized = src.match(/className="[^"]*btn-(?:ghost|primary) btn-sm[^"]*"/g) ?? [];
    expect(sized.length).toBeGreaterThanOrEqual(4);
    for (const b of sized) expect(b, b).toMatch(/!h-10 sm:!h-8/);
  });
});
