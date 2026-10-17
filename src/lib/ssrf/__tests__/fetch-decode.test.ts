import { describe, expect, it } from "vitest";
import { decodeUtf8 } from "../fetch";

const same = (b: Buffer) => expect(decodeUtf8(b)).toBe(b.toString("utf8"));

describe("decodeUtf8 ≡ Buffer#toString('utf8') (thay thế để typecheck được trong chương trình Worker)", () => {
  it("văn bản hợp lệ: ASCII, tiếng Việt, emoji, rỗng", () => {
    for (const s of ["", "hello", "Xin chào — Việt Nam 🐾", "<html>\n\t</html>"]) same(Buffer.from(s, "utf8"));
  });
  it("giữ nguyên BOM ở đầu (không bị nuốt)", () => {
    const b = Buffer.concat([Buffer.from([0xef, 0xbb, 0xbf]), Buffer.from("abc")]);
    expect(decodeUtf8(b).charCodeAt(0)).toBe(0xfeff);
    same(b);
  });
  it("byte lỗi: chuỗi bị cắt giữa chừng, overlong, surrogate mã hoá, byte lẻ, 0xFF", () => {
    for (const bytes of [[0xe2, 0x82], [0xc0, 0xaf], [0xed, 0xa0, 0x80], [0xf8, 0x88, 0x80, 0x80, 0x80], [0x80], [0xff, 0xfe], [0xf0, 0x9f, 0x90], [0x61, 0xe2, 0x82, 0x62]]) same(Buffer.from(bytes));
  });
  it("ngẫu nhiên 3000 mẫu byte bất kỳ cho kết quả y hệt Buffer", () => {
    let seed = 12345;
    const rnd = () => (seed = (seed * 1103515245 + 12345) & 0x7fffffff) / 0x7fffffff;
    for (let i = 0; i < 3000; i++) same(Buffer.from(Array.from({ length: Math.floor(rnd() * 24) }, () => Math.floor(rnd() * 256))));
  });
  it("chấp nhận Buffer lẫn Uint8Array con (subarray) của vùng nhớ lớn hơn", () => {
    const big = Buffer.from("xxxxhelloyyyy");
    expect(decodeUtf8(big.subarray(4, 9))).toBe("hello");
  });
});
