/**
 * Nhãn hiển thị tiếng Việt. Dữ liệu bên trong (DB, mã luật, khoá danh mục) giữ nguyên ID tiếng Anh ổn định;
 * chỉ lớp hiển thị mới dịch. KHÔNG đổi các khoá này.
 */
import type { Category, Confidence, FindingStatus, Severity } from "./scanner/types";

export const CATEGORY_LABEL: Record<Category, string> = {
  "Transport Security": "Bảo mật đường truyền",
  Headers: "HTTP Header bảo mật",
  "Browser Security": "Bảo mật trình duyệt",
  "Cookies & Sessions": "Cookie & phiên đăng nhập",
  Exposure: "Lộ thông tin",
  Configuration: "Cấu hình hệ thống",
  Privacy: "Quyền riêng tư",
};

export const SEV_LABEL: Record<Severity, string> = {
  critical: "Nghiêm trọng",
  high: "Cao",
  medium: "Trung bình",
  low: "Thấp",
  info: "Thông tin",
};

export const CONFIDENCE_LABEL: Record<Confidence, string> = { high: "cao", medium: "trung bình", low: "thấp" };

export const STATUS_LABEL: Record<FindingStatus, string> = { pass: "Đạt", fail: "Có vấn đề", info: "Ghi chú", unknown: "Chưa kiểm tra được" };

export const SCAN_STATUS_LABEL: Record<string, string> = {
  queued: "Đang chờ trong hàng đợi",
  validating: "Đang kiểm tra địa chỉ",
  scanning_transport: "Đang quét đường truyền (HTTPS/TLS)",
  checking_headers: "Đang kiểm tra HTTP header",
  analyzing_client: "Đang phân tích mã công khai phía trình duyệt",
  generating_report: "Đang tạo báo cáo",
  completed: "Hoàn tất",
  failed: "Thất bại",
};
