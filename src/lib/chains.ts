import type { Finding, Severity } from "./scanner/types";

/**
 * Chuỗi tấn công: nhiều phát hiện nhỏ cộng lại thành một con đường tấn công thực tế. Hoàn toàn xác định (không AI):
 * mỗi chuỗi khai báo các “nhóm điều kiện”, một nhóm được thoả khi có BẤT KỲ luật nào trong nhóm đang báo vấn đề.
 * Chuỗi hiện ra khi mọi nhóm bắt buộc được thoả; nhóm tuỳ chọn chỉ làm chuỗi nghiêm trọng hơn. Đây là suy luận từ cấu hình quan sát được,
 * không phải bằng chứng đã khai thác được.
 */
export interface Chain { id: string; title: string; summary: string; steps: string[]; cut: string; severity: Severity; ruleIds: string[]; complete: boolean }
interface Def { id: string; title: string; summary: string; steps: string[]; cut: string; groups: string[][]; required: number[] }

const DEFS: Def[] = [
  {
    id: "xss-session", title: "Chiếm phiên đăng nhập qua XSS",
    summary: "CSP yếu cho phép mã chèn vào trang chạy, và phiên đăng nhập nằm ở nơi mã đó đọc được.",
    steps: ["Kẻ tấn công tìm điểm chèn mã (DOM XSS, thư viện cũ hoặc script bên thứ ba bị chiếm).", "CSP quá lỏng nên trình duyệt vẫn chạy mã đó.", "Mã đọc token/cookie rồi gửi ra ngoài và đăng nhập thay nạn nhân."],
    cut: "Siết CSP (nonce + strict-dynamic) trước: nó chặn được cả ba bước.",
    groups: [["headers.csp", "adv.csp-analysis"], ["adv.dom-xss-flow", "exposure.outdated-libraries", "adv.supply-chain", "browser.third-party-integrity"], ["cookies.flags", "adv.web-storage-secrets"]], required: [0, 1],
  },
  {
    id: "downgrade", title: "Hạ cấp xuống HTTP để nghe lén",
    summary: "Thiếu HSTS và còn đường vào bằng HTTP nên kẻ đứng giữa mạng có thể kéo khách ra khỏi HTTPS.",
    steps: ["Khách gõ địa chỉ không có https:// hoặc mạng công cộng bị can thiệp.", "Kết nối đầu tiên đi qua HTTP vì trình duyệt chưa được buộc dùng HTTPS.", "Kẻ đứng giữa đọc hoặc sửa nội dung, đánh cắp phiên/mật khẩu."],
    cut: "Bật HSTS (kèm includeSubDomains và preload) và chuyển hướng HTTP→HTTPS bằng 301.",
    groups: [["tls.hsts", "tls.hsts-preload"], ["tls.http-to-https-redirect", "adv.redirect-chain", "tls.www-consistency"], ["browser.mixed-content", "tls.insecure-login-form"]], required: [0, 1],
  },
  {
    id: "mail-spoof", title: "Giả mạo email từ tên miền của bạn",
    summary: "DMARC không thực thi nên thư giả mạo vẫn tới hộp thư người nhận.",
    steps: ["Kẻ lừa đảo gửi email mạo danh tên miền (hoá đơn, đặt lại mật khẩu).", "SPF/DMARC không yêu cầu từ chối thư không hợp lệ.", "Khách hàng hoặc nhân viên tin thư và nhập thông tin vào trang giả."],
    cut: "Đặt DMARC p=quarantine rồi reject, SPF kết thúc bằng -all.",
    groups: [["adv.spf-deep"], ["adv.dmarc-deep", "config.dns-email-security"]], required: [1],
  },
  {
    id: "recon", title: "Do thám dễ dàng để tìm điểm yếu",
    summary: "Mã nguồn gốc, thông tin phiên bản hoặc lỗi chi tiết lộ ra giúp kẻ tấn công chọn đúng công cụ.",
    steps: ["Kẻ tấn công đọc source map, ghi chú, địa chỉ nội bộ hoặc tệp cấu hình công khai.", "Trang lỗi hoặc header cho biết đúng phiên bản phần mềm.", "Họ tra lỗ hổng đã biết của đúng phiên bản và nhắm vào đường dẫn API vừa thấy."],
    cut: "Tắt source map và chi tiết lỗi ở bản chạy thật; ẩn phiên bản máy chủ.",
    groups: [["exposure.source-maps", "exposure.secrets", "exposure.public-config", "exposure.internal-references", "exposure.html-comments"], ["config.server-disclosure", "exposure.error-page-disclosure", "config.debug-headers"], ["adv.endpoint-map", "adv.graphql-surface"]], required: [0, 1],
  },
  {
    id: "supply-chain", title: "Chèn mã qua chuỗi cung ứng script",
    summary: "Script bên ngoài không được kiểm soát và CSP không chặn nguồn lạ.",
    steps: ["Nhà cung cấp CDN hoặc tên miền script bị xâm nhập, thay nội dung.", "Trang của bạn nạp bản đã bị sửa vì không ghim phiên bản hoặc kiểm tra SRI.", "Mã độc chạy với đầy đủ quyền trên trang."],
    cut: "Ghim phiên bản + SRI, hoặc tự lưu thư viện trên tên miền của bạn.",
    groups: [["adv.supply-chain", "browser.third-party-integrity"], ["headers.csp", "adv.csp-analysis"]], required: [0, 1],
  },
  {
    id: "cache-leak", title: "Rò rỉ phiên qua bộ nhớ đệm dùng chung",
    summary: "Cookie phiên có thể bị CDN/proxy lưu lại và phát cho người khác.",
    steps: ["Người dùng đầu tiên nhận phản hồi có Set-Cookie.", "CDN/proxy lưu phản hồi vì chính sách cache cho phép dùng chung.", "Người kế tiếp nhận lại cookie đó và vào thẳng tài khoản."],
    cut: "Đặt Cache-Control: private, no-store cho mọi phản hồi có cookie.",
    groups: [["adv.shared-cache-leak", "headers.cache-policy", "cookies.cache-control-sensitive"], ["adv.cookie-scope", "cookies.flags"]], required: [0],
  },
  {
    id: "clickjack", title: "Đánh lừa bấm nút ẩn (clickjacking)",
    summary: "Trang có thể bị nhúng vào khung của website khác và cookie vẫn được gửi kèm.",
    steps: ["Kẻ tấn công nhúng trang của bạn vào khung vô hình.", "Khách tưởng bấm nút trang khác nhưng thực ra bấm nút trên trang bạn.", "Cookie phiên được gửi kèm nên hành động được thực hiện với quyền của khách."],
    cut: "Thêm frame-ancestors 'none' (hoặc X-Frame-Options: DENY) và SameSite=Lax cho cookie.",
    groups: [["headers.frame-protection"], ["cookies.flags", "adv.cookie-scope"]], required: [0, 1],
  },
];

const RANK: Severity[] = ["info", "low", "medium", "high", "critical"];
const present = (fs: Finding[], id: string) => fs.filter((f) => f.ruleId === id && (f.status === "fail" || f.status === "info"));

export function attackChains(findings: Finding[]): Chain[] {
  const out: Chain[] = [];
  for (const d of DEFS) {
    const hits = d.groups.map((g) => g.flatMap((id) => present(findings, id)));
    if (!d.required.every((i) => hits[i]!.length > 0)) continue;
    const involved = hits.flat();
    const ruleIds = [...new Set(involved.map((f) => f.ruleId))];
    const worst = involved.reduce<Severity>((a, f) => (RANK.indexOf(f.severity) > RANK.indexOf(a) ? f.severity : a), "info");
    const complete = hits.every((h) => h.length > 0);
    // chuỗi hoàn chỉnh (cả nhóm tuỳ chọn) nâng một bậc, tối đa High: suy luận từ cấu hình, không phải bằng chứng khai thác
    const bumped = complete && RANK.indexOf(worst) < RANK.indexOf("high") ? RANK[RANK.indexOf(worst) + 1]! : worst;
    out.push({ id: d.id, title: d.title, summary: d.summary, steps: d.steps, cut: d.cut, severity: bumped, ruleIds, complete });
  }
  return out.sort((a, b) => RANK.indexOf(b.severity) - RANK.indexOf(a.severity));
}
