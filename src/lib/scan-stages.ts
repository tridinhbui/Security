import type { ScanStatus } from "./db-types";

/**
 * Chín bước hiển thị, NHÓM THEO giai đoạn thật mà máy chủ báo (queued → … → completed).
 * Khi một giai đoạn đang chạy, mọi bước thuộc nhóm đó cùng hiện "đang quét" — chúng tôi không giả lập
 * việc từng bước nhỏ hoàn tất lần lượt vì máy chủ không báo ở mức chi tiết đó.
 */
export interface StageStep { id: string; label: string; detail: string }
export interface StageGroup { server: ScanStatus; steps: StageStep[] }

export const STAGE_GROUPS: StageGroup[] = [
  { server: "queued", steps: [{ id: "init", label: "Khởi tạo phiên quét an toàn", detail: "Xếp hàng và cấp tài nguyên cô lập" }] },
  { server: "validating", steps: [{ id: "resolve", label: "Phân giải mục tiêu", detail: "Kiểm tra URL, tra DNS và chặn địa chỉ nội bộ (chống SSRF)" }] },
  { server: "scanning_transport", steps: [{ id: "tls", label: "Kiểm tra HTTPS/TLS", detail: "Chứng chỉ, phiên bản TLS, HSTS, chuyển hướng HTTP→HTTPS" }] },
  { server: "checking_headers", steps: [{ id: "headers", label: "Kiểm tra HTTP header bảo mật", detail: "CSP, chống clickjacking, CORS, cờ cookie" }] },
  {
    server: "analyzing_client",
    steps: [
      { id: "exposure", label: "Phân tích endpoint công khai", detail: "robots.txt, sitemap, security.txt, source map, trang lỗi" },
      { id: "client", label: "Rà soát rủi ro phía trình duyệt", detail: "Script, khoá bí mật bị lộ, thư viện lỗi thời" },
    ],
  },
  {
    server: "generating_report",
    steps: [
      { id: "config", label: "Đánh giá cấu hình", detail: "DNS, bảo mật email, chuyển hướng, quyền riêng tư" },
      { id: "score", label: "Tính điểm rủi ro", detail: "Trọng số mức độ × độ tin cậy" },
      { id: "report", label: "Tạo báo cáo", detail: "Bằng chứng và hướng dẫn khắc phục" },
    ],
  },
];

export const ALL_STEPS = STAGE_GROUPS.flatMap((g) => g.steps.map((s) => ({ ...s, server: g.server })));
export type StepState = "pending" | "running" | "done";

/** Trạng thái từng bước theo giai đoạn hiện tại của máy chủ. */
export function stepStates(current: ScanStatus): Record<string, StepState> {
  const idx = STAGE_GROUPS.findIndex((g) => g.server === current);
  const out: Record<string, StepState> = {};
  STAGE_GROUPS.forEach((g, i) => {
    for (const s of g.steps) out[s.id] = current === "completed" ? "done" : idx === -1 ? "pending" : i < idx ? "done" : i === idx ? "running" : "pending";
  });
  return out;
}

/** Tiến độ tổng 0..1, tăng theo số nhóm đã xong (+ nửa nhóm đang chạy). */
export function progressFraction(current: ScanStatus): number {
  if (current === "completed") return 1;
  const idx = STAGE_GROUPS.findIndex((g) => g.server === current);
  return idx === -1 ? 0 : (idx + 0.5) / STAGE_GROUPS.length;
}
