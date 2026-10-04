/**
 * Chế độ dễ hiểu: tiêu đề thân thiện và bảng thuật ngữ nhỏ. Chỉ phục vụ hiển thị —
 * logic phát hiện không phụ thuộc file này, và luật chưa có ở đây sẽ dùng chính tiêu đề của nó.
 */
export const PLAIN_TITLES: Record<string, string> = {
  "tls.https-available": "Website có “ổ khoá” HTTPS hoạt động không?",
  "tls.certificate-expiry": "Chứng chỉ ổ khoá có sắp hết hạn không?",
  "tls.certificate-strength": "Khoá mã hoá của chứng chỉ có đủ mạnh không?",
  "tls.protocol-version": "Website có từ chối mã hoá cũ, yếu không?",
  "tls.http2": "Website có dùng giao thức tải trang nhanh HTTP/2 không?",
  "tls.http-to-https-redirect": "Khách có được đưa sang phiên bản an toàn không?",
  "tls.www-consistency": "Gõ thừa hoặc thiếu “www” có vào được trang an toàn không?",
  "tls.hsts": "Trình duyệt có bị buộc luôn dùng HTTPS không?",
  "tls.insecure-login-form": "Form mật khẩu có được bảo vệ không?",
  "headers.csp": "Website có giới hạn mã nào được chạy trên trang không?",
  "headers.frame-protection": "Website khác có thể đánh lừa khách bấm vào nút ẩn không?",
  "headers.x-content-type-options": "Trình duyệt có ngừng đoán loại file không?",
  "headers.broken": "Các thiết lập an toàn có được viết đúng không?",
  "headers.cross-origin-isolation": "Trang có được tách biệt khỏi website khác trong trình duyệt không?",
  "headers.charset": "Trang có khai báo bảng mã ký tự không?",
  "browser.mixed-content": "Trang an toàn có tải thứ gì đó qua đường không an toàn không?",
  "browser.third-party-integrity": "Script từ bên ngoài có được kiểm tra chống bị sửa không?",
  "browser.cors": "Website nào khác được đọc dữ liệu của trang này?",
  "cookies.flags": "Cookie đăng nhập có được khoá chặt không?",
  "cookies.cache-control-sensitive": "Trang riêng tư có tránh bị lưu vào bộ nhớ đệm không?",
  "exposure.secrets": "Có mật khẩu hay khoá bí mật nào lộ trong mã trang không?",
  "exposure.public-config": "Những thiết lập nào ai cũng nhìn thấy được?",
  "exposure.source-maps": "Mã nguồn gốc của website có tải về được không?",
  "exposure.robots-txt": "Tệp hướng dẫn trình thu thập có tiết lộ gì không?",
  "exposure.sitemap-xml": "Có danh sách trang cho công cụ tìm kiếm không?",
  "exposure.security-txt": "Nhà nghiên cứu có biết cách báo lỗi cho bạn không?",
  "exposure.outdated-libraries": "Website có dùng thư viện cũ đã biết lỗi không?",
  "exposure.subdomain-takeover": "Tên miền có thể bị người khác chiếm giữ không?",
  "exposure.error-page-disclosure": "Trang báo lỗi có để lộ chi tiết nội bộ không?",
  "config.server-disclosure": "Máy chủ có công bố phiên bản phần mềm không?",
  "config.technology": "Website được xây bằng công nghệ gì?",
  "config.suspicious-redirects": "Khách có bị chuyển tới nơi bất ngờ không?",
  "config.dns-email-security": "Có ai giả mạo được email từ tên miền này không?",
  "config.auth-surface": "Nhìn từ bên ngoài, đăng nhập hoạt động thế nào?",
  "privacy.referrer-policy": "Website khác biết được bao nhiêu về nơi khách đến?",
  "privacy.permissions-policy": "Camera, micro và vị trí có bị khoá không?",
  "privacy.third-party-origins": "Những công ty nào khác nhìn thấy khách của bạn?",
  "privacy.trackers": "Website có gắn công cụ theo dõi khách không?",
};

export const GLOSSARY: Record<string, string> = {
  HTTPS: "“Ổ khoá” trên thanh địa chỉ. Nó mã hoá dữ liệu giữa khách và website để người khác không đọc hay sửa được.",
  TLS: "Công nghệ mã hoá đứng sau HTTPS.",
  HSTS: "Quy tắc báo cho trình duyệt “chỉ nói chuyện với website này qua kết nối an toàn”.",
  CSP: "Danh sách những nơi mà trang của bạn được phép nạp mã. Nơi nào ngoài danh sách đều bị chặn.",
  "Content-Security-Policy": "Danh sách những nơi mà trang của bạn được phép nạp mã. Nơi nào ngoài danh sách đều bị chặn.",
  XSS: "Kiểu tấn công chèn mã của kẻ xấu vào trang của bạn để nó chạy trên máy khách truy cập.",
  CORS: "Quy tắc quyết định website nào khác được đọc phản hồi từ website của bạn trong trình duyệt của khách.",
  CSRF: "Kiểu tấn công đánh lừa trình duyệt của người đang đăng nhập làm điều gì đó trên website của bạn mà họ không hay biết.",
  clickjacking: "Giấu trang của bạn trong khung vô hình để khách bấm vào những nút mà họ không nhìn thấy.",
  SRI: "Một “dấu vân tay” giúp trình duyệt từ chối script nếu có ai đó đã sửa nó.",
  "Subresource Integrity": "Một “dấu vân tay” giúp trình duyệt từ chối script nếu có ai đó đã sửa nó.",
  cookie: "Mẩu thông tin nhỏ website lưu trong trình duyệt, thường để nhớ rằng khách đã đăng nhập.",
  Cookie: "Mẩu thông tin nhỏ website lưu trong trình duyệt, thường để nhớ rằng khách đã đăng nhập.",
  HttpOnly: "Ngăn script trên trang đọc cookie, nhờ vậy script bị chèn vào không đánh cắp được phiên đăng nhập.",
  Secure: "Chỉ gửi cookie qua kết nối có ổ khoá (HTTPS).",
  SameSite: "Ngăn website khác khiến trình duyệt gửi kèm cookie của bạn.",
  "source map": "File giúp biến mã đã nén trên production về lại mã nguồn gốc dễ đọc của bạn.",
  "source maps": "File giúp biến mã đã nén trên production về lại mã nguồn gốc dễ đọc của bạn.",
  SPF: "Danh sách công khai các máy chủ được phép gửi email cho tên miền của bạn.",
  DMARC: "Chính sách bảo nhà cung cấp email xử lý thế nào với thư giả mạo tên miền của bạn.",
  CAA: "Ghi chú trong DNS nói rõ những đơn vị nào được cấp chứng chỉ cho tên miền của bạn.",
  DNSSEC: "Chữ ký số cho bản ghi DNS, giúp chắc chắn khách được dẫn tới đúng máy chủ chứ không phải máy chủ giả.",
  "MTA-STS": "Quy tắc buộc các máy chủ email gửi thư tới bạn phải dùng kết nối mã hoá.",
  "mixed content": "Trang an toàn nhưng vẫn tải một số thứ qua kết nối không an toàn.",
  Referrer: "Thông tin “bạn đến từ đâu” mà trình duyệt gửi cho website tiếp theo.",
  "Row Level Security": "Quy tắc trong cơ sở dữ liệu quyết định mỗi người dùng được đọc hay sửa những dòng nào.",
  "security.txt": "Một tệp công khai nhỏ cho nhà nghiên cứu bảo mật biết cách liên hệ với bạn.",
  nosniff: "Báo trình duyệt tin vào loại file được khai báo thay vì tự đoán.",
  "subdomain takeover": "Kẻ xấu chiếm một tên miền phụ của bạn vì nó vẫn trỏ tới dịch vụ đã bị xoá.",
  "stack trace": "Bản ghi các bước chạy mã ngay trước khi gặp lỗi; có thể tiết lộ tên file và cấu trúc nội bộ.",
  "CVE": "Mã số công khai của một lỗ hổng bảo mật đã được ghi nhận.",
  ALPN: "Cách trình duyệt và máy chủ thoả thuận dùng giao thức nào (như HTTP/2) khi bắt tay TLS.",
  wildcard: "Chứng chỉ dùng chung cho mọi tên miền phụ (dạng *.example.com).",
};

/** Mục thuật ngữ có xuất hiện trong văn bản đã cho. */
export function glossaryFor(...texts: string[]): { term: string; meaning: string }[] {
  const hay = texts.join(" \n ");
  const out: { term: string; meaning: string }[] = [];
  const seen = new Set<string>();
  for (const [term, meaning] of Object.entries(GLOSSARY)) {
    if (new RegExp(`(^|[^\\p{L}\\d])${term.replace(/[.*+?^${}()|[\]\\]/g, "\\$&")}([^\\p{L}\\d]|$)`, "iu").test(hay) && !seen.has(meaning)) {
      seen.add(meaning);
      out.push({ term, meaning });
    }
  }
  return out.slice(0, 4);
}
