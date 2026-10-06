import type { Finding } from "./scanner/types";

/**
 * Tạo "prompt" để người dùng dán vào AI viết code (Cursor, Claude Code, Copilot…) nhằm tự sửa lỗi.
 * Hoàn toàn là ghép chuỗi từ kết quả quét — không gọi AI. Thuần hàm, chạy được ở trình duyệt.
 */
export function buildFixPrompt(f: Finding, host: string, platforms: string[] = []): string {
  const r = f.remediation;
  const L: string[] = [
    `Bạn là kỹ sư bảo mật giúp mình sửa một lỗ hổng cấu hình cho website ${host}.`,
    "",
    `## Vấn đề (mức ${f.severity}): ${f.title}`,
    f.summary,
    "",
    `Vì sao nguy hiểm: ${f.explanation}`,
  ];
  if (f.affectedUrl) L.push("", `Địa chỉ bị ảnh hưởng: ${f.affectedUrl}`);
  if (f.evidence.length) L.push("", "Bằng chứng từ bộ quét:", ...f.evidence.slice(0, 6).map((e) => `- ${e}`));
  L.push("", `Hệ thống mình dùng: ${platforms.length ? platforms.join(", ") : "chưa rõ — hãy xem cấu trúc dự án để tự xác định trước khi sửa"}.`);
  if (r) {
    L.push("", "## Hướng dẫn sửa gợi ý từ bộ quét", r.summary, ...(r.steps ?? []).map((s, i) => `${i + 1}. ${s}`));
    for (const s of r.snippets.slice(0, 3)) L.push("", `Ví dụ (${s.label}):`, "```", s.code, "```");
  }
  L.push(
    "", "## Yêu cầu",
    "1. Tìm đúng file cấu hình hoặc mã trong dự án này cần sửa (đừng đoán, hãy mở và đọc).",
    "2. Sửa tối thiểu, đúng phạm vi vấn đề này, không đổi tính năng khác.",
    "3. Giải thích ngắn gọn bằng tiếng Việt, dễ hiểu, bạn đã đổi gì và vì sao.",
    "4. Nếu thay đổi có rủi ro làm hỏng website (ví dụ chặn nhầm script), hãy nói rõ cách thử và cách quay lại.",
    `5. Cho mình lệnh để kiểm tra lại sau khi triển khai, ví dụ curl -sI https://${host} và chỉ ra dòng cần thấy.`,
  );
  return L.join("\n");
}

/** Một prompt gộp cho nhiều vấn đề, đã sắp theo mức nghiêm trọng. */
export function buildAllPrompt(findings: Finding[], host: string, platforms: string[] = []): string {
  const order = ["critical", "high", "medium", "low", "info"];
  const list = [...findings].sort((a, b) => order.indexOf(a.severity) - order.indexOf(b.severity)).slice(0, 12);
  const L = [
    `Bạn là kỹ sư bảo mật. Mình vừa quét ${host} và có ${list.length} vấn đề cần sửa. Hãy xử lý lần lượt từ trên xuống.`,
    `Hệ thống mình dùng: ${platforms.length ? platforms.join(", ") : "chưa rõ — hãy xem cấu trúc dự án để xác định"}.`,
    "",
  ];
  list.forEach((f, i) => {
    L.push(`### ${i + 1}. [${f.severity}] ${f.title}`, f.summary);
    if (f.remediation) L.push(`Gợi ý: ${f.remediation.summary}`);
    L.push("");
  });
  L.push("Với mỗi vấn đề: tìm đúng file trong dự án, sửa tối thiểu, giải thích ngắn bằng tiếng Việt, và đưa lệnh kiểm tra lại. Làm xong một vấn đề rồi mới sang vấn đề tiếp theo, và hỏi mình nếu có thay đổi rủi ro.");
  return L.join("\n");
}
