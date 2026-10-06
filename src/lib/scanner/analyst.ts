/**
 * Góc nhìn của analyst cho từng phát hiện:
 *  - statement / sub: câu khẳng định nói thẳng sự việc (không phải câu hỏi), để đọc lướt là hiểu issue ngay;
 *  - origin: NGUỒN GỐC lỗi — "chưa hề nghĩ tới" khác "đã nghĩ tới nhưng làm sai" khác "bỏ sót bảo trì" khác "lộ do sơ suất".
 *    Mỗi loại chỉ ra quy trình nào đang thiếu (checklist, kiểm thử sau triển khai, giám sát, rà soát trước phát hành);
 *  - repro: lệnh CHỈ ĐỌC để analyst tự tái hiện/xác minh phát hiện, không cần tin công cụ.
 */
export type OriginKind = "absent" | "misconfigured" | "lapse" | "exposure";
export interface Origin { kind: OriginKind; label: string; meaning: string; rootCause: string }

export const ORIGINS: Record<OriginKind, Omit<Origin, "kind">> = {
  absent: { label: "Chưa triển khai", meaning: "Biện pháp bảo vệ này hoàn toàn chưa có: nhiều khả năng chưa từng được cân nhắc.", rootCause: "Thiếu checklist bảo mật khi xây dựng hoặc phát hành." },
  misconfigured: { label: "Cấu hình sai hoặc yếu", meaning: "Đã có ý định bảo vệ nhưng triển khai chưa đúng hoặc chưa đủ chặt.", rootCause: "Thiếu bước kiểm thử cấu hình sau khi triển khai." },
  lapse: { label: "Bỏ sót bảo trì", meaning: "Từng ổn nhưng không được theo dõi: hết hạn, lỗi thời hoặc tài nguyên bị bỏ quên.", rootCause: "Thiếu giám sát và lịch rà soát định kỳ." },
  exposure: { label: "Lộ do sơ suất", meaning: "Thông tin không định công khai lại đang công khai.", rootCause: "Thiếu bước rà soát nội dung trước khi phát hành." },
};

interface Entry { statement: string; sub: string; origin: OriginKind }
export const ANALYST: Record<string, Entry> = {
  "tls.https-available": { statement: "Khách hàng đang truy cập website không có mã hoá", sub: "Dữ liệu khách gửi và nhận có thể bị đọc hoặc sửa trên đường truyền", origin: "absent" },
  "tls.hsts": { statement: "Trình duyệt chưa bị buộc phải dùng kết nối an toàn", sub: "Lần truy cập đầu tiên của khách vẫn có thể đi qua đường dẫn không bảo mật", origin: "absent" },
  "tls.hsts-preload": { statement: "Lần truy cập đầu tiên của khách chưa được bảo vệ", sub: "Website chưa nằm trong danh sách HTTPS cài sẵn của trình duyệt", origin: "absent" },
  "tls.certificate-expiry": { statement: "Chứng chỉ bảo mật sắp hết hạn", sub: "Khi hết hạn, khách sẽ thấy cảnh báo đỏ và không vào được website", origin: "lapse" },
  "tls.cipher-suite": { statement: "Kết nối đang dùng kiểu mã hoá đã lỗi thời", sub: "Độ bền mã hoá thấp hơn chuẩn hiện tại", origin: "misconfigured" },
  "adv.certificate-hygiene": { statement: "Chứng chỉ chưa được quản lý theo thực hành tốt nhất", sub: "Phạm vi hoặc thời hạn chứng chỉ rộng hơn mức cần thiết", origin: "misconfigured" },
  "tls.http-to-https-redirect": { statement: "Khách hàng chưa được đưa sang phiên bản an toàn", sub: "Khách hàng vẫn có thể truy cập trang web bằng đường dẫn không có bảo mật", origin: "absent" },
  "tls.www-consistency": { statement: "Hai địa chỉ của website không được xử lý giống nhau", sub: "Khách vào địa chỉ có hoặc không có www có thể gặp lỗi hoặc bản kém an toàn", origin: "misconfigured" },
  "adv.redirect-chain": { statement: "Khách bị chuyển hướng qua nhiều bước không cần thiết", sub: "Một số bước đi qua đường dẫn không bảo mật", origin: "misconfigured" },
  "config.suspicious-redirects": { statement: "Khách có thể bị đưa sang website khác", sub: "Chuyển hướng dẫn ra ngoài hoặc hạ xuống đường dẫn không bảo mật", origin: "misconfigured" },
  "tls.insecure-login-form": { statement: "Mật khẩu của khách có thể đi qua đường truyền không an toàn", sub: "Form đăng nhập gửi dữ liệu không được mã hoá", origin: "misconfigured" },
  "browser.form-targets": { statement: "Mật khẩu của khách được gửi sang website khác", sub: "Form đăng nhập gửi dữ liệu ra ngoài tên miền của bạn", origin: "misconfigured" },
  "adv.form-method": { statement: "Dữ liệu nhạy cảm của khách nằm ngay trên đường dẫn", sub: "Form gửi bằng GET nên dữ liệu lưu vào lịch sử trình duyệt và nhật ký máy chủ", origin: "misconfigured" },
  "headers.csp": { statement: "Trình duyệt chưa bị giới hạn chạy mã lạ trên website", sub: "Nếu kẻ tấn công chèn được mã, không có lớp nào chặn nó", origin: "absent" },
  "adv.csp-analysis": { statement: "Chính sách chặn mã lạ còn chỗ hở", sub: "CSP có nhưng một số nguồn hoặc cấu hình cho phép vượt qua", origin: "misconfigured" },
  "headers.frame-protection": { statement: "Website có thể bị nhúng vào trang của kẻ khác", sub: "Khách có thể bị dụ bấm vào nút ẩn (clickjacking)", origin: "absent" },
  "headers.x-content-type-options": { statement: "Trình duyệt được phép tự đoán loại nội dung", sub: "Tệp tải lên có thể bị chạy như mã", origin: "absent" },
  "headers.broken": { statement: "Một số lớp bảo vệ được bật nhưng không hoạt động", sub: "Header sai cú pháp nên trình duyệt bỏ qua hoàn toàn", origin: "misconfigured" },
  "headers.deprecated": { statement: "Website còn dùng cơ chế bảo vệ đã bị loại bỏ", sub: "Cấu hình cũ không còn tác dụng hoặc gây rủi ro vận hành", origin: "lapse" },
  "headers.cross-origin-isolation": { statement: "Website chưa được cô lập khỏi các trang khác trong trình duyệt", sub: "Giảm khả năng chống rò rỉ dữ liệu giữa các trang", origin: "absent" },
  "headers.cache-policy": { statement: "Không rõ ai được phép lưu bản sao của trang", sub: "Trang có thể bị proxy hoặc CDN lưu lại và phát cho người khác", origin: "absent" },
  "adv.header-consistency": { statement: "Các trang của website được bảo vệ không đồng đều", sub: "Có trang thiếu lớp bảo vệ mà trang chủ có", origin: "lapse" },
  "adv.shared-cache-leak": { statement: "Phiên đăng nhập của khách có thể bị phát cho người khác", sub: "Trang chứa phiên được phép lưu trong bộ nhớ đệm dùng chung", origin: "misconfigured" },
  "privacy.referrer-policy": { statement: "Địa chỉ trang của khách bị gửi cho website khác", sub: "Khi khách bấm liên kết ra ngoài, bên kia biết khách vừa ở trang nào", origin: "absent" },
  "privacy.permissions-policy": { statement: "Các tính năng nhạy cảm của trình duyệt chưa bị giới hạn", sub: "Mã bên thứ ba có thể xin quyền camera hoặc vị trí qua trang của bạn", origin: "absent" },
  "cookies.flags": { statement: "Phiên đăng nhập của khách chưa được bảo vệ đầy đủ", sub: "Cookie thiếu cờ bảo vệ nên dễ bị đánh cắp hoặc gửi qua kết nối không an toàn", origin: "misconfigured" },
  "cookies.prefix": { statement: "Cookie phiên có thể bị ghi đè", sub: "Chưa dùng tiền tố bảo vệ của trình duyệt (__Host-)", origin: "absent" },
  "adv.cookie-scope": { statement: "Cookie phiên được chia sẻ với cả tên miền con", sub: "Một tên miền con yếu có thể đọc hoặc ghi đè phiên", origin: "misconfigured" },
  "browser.cors": { statement: "Website khác có thể đọc dữ liệu từ website của bạn", sub: "Chính sách CORS cho phép nguồn không được tin cậy", origin: "misconfigured" },
  "config.dns-email-security": { statement: "Ai cũng có thể giả danh email của tên miền", sub: "Thiếu hoặc yếu các bản ghi SPF, DMARC, CAA", origin: "absent" },
  "adv.spf-deep": { statement: "Bản ghi SPF có lỗi hoặc quá lỏng", sub: "Email giả danh dễ lọt, hoặc email thật bị loại", origin: "misconfigured" },
  "adv.dmarc-deep": { statement: "Chính sách DMARC chưa chặn thư giả mạo", sub: "Thư giả mạo vẫn tới hộp thư người nhận", origin: "misconfigured" },
  "config.server-disclosure": { statement: "Website tiết lộ phần mềm máy chủ đang dùng", sub: "Kẻ quét tự động biết phiên bản để thử các lỗ hổng đã công bố", origin: "exposure" },
  "exposure.error-page-disclosure": { statement: "Trang lỗi tiết lộ thông tin nội bộ", sub: "Đường dẫn, phiên bản hoặc cấu hình hiện ra khi có lỗi", origin: "exposure" },
  "exposure.html-comments": { statement: "Ghi chú nội bộ bị để lại trong mã trang", sub: "Ai bấm “Xem nguồn trang” cũng đọc được", origin: "exposure" },
  "exposure.internal-references": { statement: "Địa chỉ hệ thống nội bộ bị lộ trong mã trang", sub: "Kẻ tấn công biết thêm cấu trúc mạng nội bộ", origin: "exposure" },
  "config.debug-headers": { statement: "Thông tin gỡ lỗi đang công khai", sub: "Header gỡ lỗi tiết lộ kiến trúc hoặc dẫn tới trang debug", origin: "exposure" },
  "exposure.security-txt": { statement: "Chưa có đầu mối nhận báo cáo lỗ hổng", sub: "Người phát hiện lỗi thiện chí không biết báo cho ai", origin: "absent" },
  "browser.mixed-content": { statement: "Trang an toàn đang tải tài nguyên không an toàn", sub: "Một số tài nguyên đi qua đường dẫn không mã hoá", origin: "misconfigured" },
  "browser.third-party-integrity": { statement: "Mã từ bên thứ ba không được kiểm tra toàn vẹn", sub: "Nếu nhà cung cấp bị xâm nhập, mã độc chạy ngay trên website", origin: "absent" },
  "adv.supply-chain": { statement: "Website phụ thuộc mã bên thứ ba không được ghim phiên bản", sub: "Bản cập nhật độc hại sẽ chạy ngay trên website", origin: "absent" },
  "exposure.secrets": { statement: "Khoá bí mật đang công khai trong mã trang", sub: "Coi như đã lộ: cần thu hồi và cấp khoá mới", origin: "exposure" },
  "exposure.public-config": { statement: "Cấu hình dịch vụ nằm công khai trong mã trang", sub: "An toàn chỉ khi quy tắc truy cập dữ liệu được đặt chặt", origin: "exposure" },
  "exposure.subdomain-takeover": { statement: "Một tên miền con đang trỏ vào tài nguyên không còn tồn tại", sub: "Người khác có thể đăng ký tài nguyên đó và chiếm tên miền con", origin: "lapse" },
  "exposure.outdated-libraries": { statement: "Website đang dùng thư viện đã có lỗ hổng công bố", sub: "Kẻ tấn công có thể dùng lỗ hổng đã biết của đúng phiên bản", origin: "lapse" },
  "exposure.robots-txt": { statement: "robots.txt tiết lộ đường dẫn nhạy cảm", sub: "Gợi ý cho kẻ tấn công nên đi đâu", origin: "exposure" },
  "tls.certificate-strength": { statement: "Khoá của chứng chỉ chưa đủ mạnh theo chuẩn hiện tại", sub: "Khoá ngắn hoặc thời hạn quá dài làm giảm độ tin cậy của kết nối", origin: "misconfigured" },
  "tls.protocol-version": { statement: "Máy chủ còn chấp nhận phiên bản TLS đã lỗi thời", sub: "Kết nối có thể bị hạ xuống phiên bản có điểm yếu đã biết", origin: "misconfigured" },
  "tls.http2": { statement: "Máy chủ chưa dùng giao thức hiện đại HTTP/2", sub: "Tải trang chậm hơn và thiếu một số cải tiến bảo mật của giao thức mới", origin: "absent" },
  "headers.charset": { statement: "Trang không khai báo bảng mã ký tự rõ ràng", sub: "Trình duyệt phải tự đoán bảng mã, mở đường cho một số kiểu chèn mã", origin: "absent" },
  "cookies.cache-control-sensitive": { statement: "Trang đăng nhập có thể bị lưu lại trong bộ nhớ đệm", sub: "Người dùng sau trên cùng máy hoặc proxy có thể xem lại trang của người trước", origin: "misconfigured" },
  "exposure.source-maps": { statement: "Mã nguồn gốc của website tải về được công khai", sub: "Source map giúp ai cũng đọc được mã nguồn, đường dẫn API và đôi khi cả bí mật", origin: "exposure" },
  "config.http-methods": { statement: "Máy chủ công bố những thao tác không cần thiết", sub: "Phương thức như TRACE hoặc PUT được công bố ở trang công khai", origin: "misconfigured" },
  "adv.dom-xss-flow": { statement: "Mã JavaScript đưa dữ liệu không tin cậy vào trang", sub: "Dữ liệu từ URL hoặc nguồn ngoài chảy tới nơi chèn HTML, có nguy cơ DOM XSS", origin: "misconfigured" },
  "adv.postmessage": { statement: "Trang nhận tin nhắn từ website khác mà không kiểm tra nguồn", sub: "Website lạ có thể gửi dữ liệu điều khiển hành vi của trang", origin: "misconfigured" },
  "adv.web-storage-secrets": { statement: "Token đăng nhập được lưu ở nơi mã JavaScript đọc được", sub: "Một lỗi XSS nhỏ đủ để đánh cắp phiên của người dùng", origin: "misconfigured" },
  "adv.endpoint-map": { statement: "Danh sách API và đường dẫn quản trị lộ trong mã trang", sub: "Kẻ tấn công không cần dò tìm vẫn biết nên nhắm vào đâu", origin: "exposure" },
  "adv.graphql-surface": { statement: "GraphQL cho phép xem toàn bộ cấu trúc dữ liệu", sub: "Introspection mở giúp kẻ tấn công liệt kê mọi truy vấn có thể gọi", origin: "misconfigured" },
  "privacy.trackers": { statement: "Trang nạp trình theo dõi của bên thứ ba", sub: "Hành vi của khách được chia sẻ với các dịch vụ bên ngoài", origin: "absent" },
  "privacy.third-party-origins": { statement: "Trang phụ thuộc nhiều dịch vụ bên thứ ba", sub: "Mỗi bên thứ ba thêm một điểm có thể bị xâm nhập hoặc làm lộ dữ liệu khách", origin: "absent" },
  "exposure.sitemap-xml": { statement: "Sơ đồ website liệt kê đường dẫn không định công khai", sub: "Kẻ tấn công biết thêm các điểm vào", origin: "exposure" },
};

/** Một số luật có hai biến thể (chưa có / có nhưng yếu): nguồn gốc suy từ tiêu đề phát hiện. */
export function originFor(ruleId: string, title: string): Origin {
  let kind: OriginKind = ANALYST[ruleId]?.origin ?? "misconfigured";
  const weak = /(yếu|không hợp lệ|sai|quá ngắn|p=none|\+all|\?all|vượt|nhiều hơn một|phản chiếu|cho phép bộ nhớ đệm|vô hiệu)/i.test(title);
  const missing = /(thiếu|chưa|không có|không khai báo)/i.test(title);
  if (["headers.csp", "tls.hsts", "headers.cache-policy", "config.dns-email-security", "exposure.security-txt"].includes(ruleId)) kind = weak && !missing ? "misconfigured" : weak ? "misconfigured" : "absent";
  if (ruleId === "exposure.security-txt" && /hết hạn/i.test(title)) kind = "lapse";
  return { kind, ...ORIGINS[kind] };
}

const HEADER_OF: Record<string, string> = {
  "tls.hsts": "strict-transport-security", "tls.hsts-preload": "strict-transport-security", "headers.csp": "content-security-policy", "adv.csp-analysis": "content-security-policy",
  "headers.frame-protection": "x-frame-options|content-security-policy", "headers.x-content-type-options": "x-content-type-options", "privacy.referrer-policy": "referrer-policy",
  "privacy.permissions-policy": "permissions-policy", "headers.cross-origin-isolation": "cross-origin-opener-policy|cross-origin-resource-policy|cross-origin-embedder-policy",
  "headers.cache-policy": "cache-control", "headers.deprecated": "public-key-pins|expect-ct|feature-policy", "headers.broken": "content-security-policy|x-frame-options|x-content-type-options|referrer-policy|permissions-policy",
  "config.server-disclosure": "server|x-powered-by|x-aspnet-version", "config.debug-headers": "x-debug-token|x-runtime|x-backend-server|x-generator|via",
};
const HOST_OK = /^[a-z0-9](?:[a-z0-9.-]*[a-z0-9])?$/;

/** Lệnh CHỈ ĐỌC để tự tái hiện phát hiện. Trả null nếu host không an toàn để chèn vào lệnh shell. */
export function reproFor(ruleId: string, host: string): string | null {
  if (!HOST_OK.test(host)) return null;
  const apex = host.replace(/^www\./, "");
  const h = HEADER_OF[ruleId];
  if (h) return `curl -sI https://${host}/ | grep -iE "^(${h}):"`;
  switch (ruleId) {
    case "tls.http-to-https-redirect": case "adv.redirect-chain": case "config.suspicious-redirects": return `curl -sIL http://${host}/ | grep -iE "^(HTTP|location)"`;
    case "tls.www-consistency": return `for h in ${apex} www.${apex}; do echo "== $h"; curl -sI https://$h/ | grep -iE "^(HTTP|location)"; done`;
    case "tls.https-available": return `curl -vI https://${host}/ 2>&1 | grep -iE "SSL|subject|expire|HTTP/"`;
    case "tls.certificate-expiry": case "adv.certificate-hygiene": return `echo | openssl s_client -servername ${host} -connect ${host}:443 2>/dev/null | openssl x509 -noout -dates -issuer -subject`;
    case "tls.cipher-suite": return `openssl s_client -connect ${host}:443 -servername ${host} </dev/null 2>/dev/null | grep -E "Protocol|Cipher"`;
    case "cookies.flags": case "cookies.prefix": case "adv.cookie-scope": case "adv.shared-cache-leak": return `curl -sI https://${host}/ | grep -i "^set-cookie:"   # đối chiếu cờ Secure / HttpOnly / SameSite`;
    case "browser.cors": return `curl -sI -H "Origin: https://origin-la.example" https://${host}/ | grep -i "^access-control"`;
    case "config.dns-email-security": case "adv.spf-deep": case "adv.dmarc-deep": return `dig +short TXT ${apex}; dig +short TXT _dmarc.${apex}; dig +short CAA ${apex}; dig +short DS ${apex}`;
    case "exposure.security-txt": return `curl -si https://${host}/.well-known/security.txt | head -5`;
    case "exposure.robots-txt": return `curl -s https://${host}/robots.txt | head -20`;
    case "tls.certificate-strength": return `echo | openssl s_client -servername ${host} -connect ${host}:443 2>/dev/null | openssl x509 -noout -text | grep -E "Public-Key|Signature Algorithm|Not (Before|After)"`;
    case "tls.protocol-version": return `for v in tls1 tls1_1 tls1_2 tls1_3; do printf "%s: " $v; echo | openssl s_client -connect ${host}:443 -servername ${host} -$v 2>&1 | grep -qE "BEGIN CERT|Cipher is" && echo chấp nhận || echo từ chối; done`;
    case "tls.http2": return `curl -sI --http2 https://${host}/ | head -1`;
    case "headers.charset": return `curl -sI https://${host}/ | grep -i "^content-type:"`;
    case "cookies.cache-control-sensitive": return `curl -sI https://${host}/ | grep -iE "^(cache-control|pragma|set-cookie):"`;
    case "exposure.source-maps": return `curl -s https://${host}/ | grep -oE "<script[^>]+src=[\"'][^\"']+" | head -10   # rồi: curl -sI <đường-dẫn-script>.map`;
    case "config.http-methods": return `curl -si -X OPTIONS https://${host}/ | grep -iE "^(HTTP|allow):"`;
    case "adv.dom-xss-flow": case "adv.postmessage": case "adv.web-storage-secrets": case "adv.endpoint-map": return `curl -s https://${host}/ | grep -oE "<script[^>]+src=[\"'][^\"']+" | head -20   # tải từng script rồi tìm mẫu liên quan`;
    case "adv.graphql-surface": return `curl -s https://${host}/ | grep -ioE "graphql[^\"' ]{0,40}" | head`;
    case "privacy.trackers": case "privacy.third-party-origins": return `curl -s https://${host}/ | grep -oE "(src|href)=[\"']https?://[^\"'/]+" | sort | uniq -c | sort -rn | head -15`;
    case "exposure.sitemap-xml": return `curl -sI https://${host}/sitemap.xml | head -3`;
    case "exposure.error-page-disclosure": return `curl -s https://${host}/khong-ton-tai-$RANDOM | head -20`;
    case "exposure.html-comments": return `curl -s https://${host}/ | grep -noE "<!--[^>]{0,160}-->" | head -20`;
    case "exposure.internal-references": return `curl -s https://${host}/ | grep -noE "(10\\.[0-9.]+|192\\.168\\.[0-9.]+|[a-z0-9-]+\\.internal)" | head`;
    case "exposure.secrets": case "exposure.public-config": case "exposure.outdated-libraries": return `curl -s https://${host}/ | grep -oE "<script[^>]+src=[\\"'][^\\"']+" | head -20   # liệt kê script để rà soát`;
    case "exposure.subdomain-takeover": return `dig +short CNAME ${host}; curl -sI https://${host}/ | head -3`;
    case "browser.mixed-content": return `curl -s https://${host}/ | grep -oE "(src|href)=[\\"']http://[^\\"' ]+" | head`;
    case "browser.third-party-integrity": case "adv.supply-chain": return `curl -s https://${host}/ | grep -oE "<(script|link)[^>]+(src|href)=[\\"']https?://[^\\"']+" | head -20`;
    case "browser.form-targets": case "tls.insecure-login-form": case "adv.form-method": return `curl -s https://${host}/ | grep -oiE "<form[^>]*>" | head`;
    default: return `curl -sI https://${host}/`;
  }
}
