import type { Severity } from "./types";

/**
 * "Nếu để 1 ngày thì sao?": hậu quả THỰC TẾ của từng vấn đề, viết có cân nhắc (không hù doạ):
 *  - today: điều có khả năng xảy ra trong một ngày nếu chưa sửa;
 *  - worst: kịch bản xấu nhất;
 *  - who: ai khai thác được và cần điều kiện gì.
 * Mức khẩn cấp mặc định theo độ nghiêm trọng; `urgency` ở đây ghi đè khi bản chất vấn đề khác với mức nghiêm trọng.
 */
export type Urgency = "now" | "week" | "later";
export interface Impact { today: string; worst: string; who: string; urgency?: Urgency }

export const IMPACT: Record<string, Impact> = {
  "tls.https-available": { today: "Mọi khách đều thấy cảnh báo “Không bảo mật” hoặc gửi dữ liệu không mã hoá; nhiều người sẽ rời đi.", worst: "Mật khẩu, cookie và nội dung bị đọc hoặc sửa trên đường truyền.", who: "Bất kỳ ai cùng mạng với khách (wifi công cộng, nhà mạng, proxy)." },
  "tls.hsts": { today: "Gần như không có gì xảy ra với khách bình thường. Rủi ro chỉ nằm ở khách dùng wifi công cộng ở lần truy cập đầu tiên.", worst: "Kẻ cùng mạng ép khách xuống HTTP rồi đọc hoặc sửa lưu lượng (SSL stripping).", who: "Kẻ tấn công cùng mạng với khách.", urgency: "week" },
  "tls.hsts-preload": { today: "Không có gì xảy ra ngay; đây là bước tăng cường cuối cùng.", worst: "Lần truy cập đầu tiên của khách vẫn có thể đi qua HTTP.", who: "Kẻ cùng mạng, chỉ ở lần truy cập đầu.", urgency: "later" },
  "tls.certificate-expiry": { today: "Nếu chứng chỉ hết hạn, mọi khách thấy cảnh báo đỏ và API gọi vào sẽ lỗi: với khách thì website coi như sập.", worst: "Gián đoạn hoàn toàn cho đến khi gia hạn.", who: "Không cần kẻ tấn công: tự gây gián đoạn.", urgency: "now" },
  "tls.cipher-suite": { today: "Kết nối vẫn được mã hoá; bộ mã hoá kém chỉ làm giảm độ bền lâu dài.", worst: "Nếu khoá riêng lộ sau này, lưu lượng đã bị ghi lại trước đó có thể bị giải mã (thiếu forward secrecy).", who: "Kẻ ghi lại lưu lượng, cần nhiều tài nguyên và thời gian.", urgency: "week" },
  "adv.certificate-hygiene": { today: "Chưa gây lỗi gì ngay; chỉ là điểm vệ sinh chứng chỉ chưa tốt.", worst: "Chứng chỉ phạm vi rộng hơn cần thiết bị lạm dụng nếu khoá riêng lộ.", who: "Kẻ lấy được khoá riêng.", urgency: "later" },
  "tls.http-to-https-redirect": { today: "Khách gõ địa chỉ không có https vẫn vào bản không mã hoá.", worst: "Kẻ cùng mạng đọc hoặc sửa lưu lượng của khách ở bản HTTP.", who: "Kẻ tấn công cùng mạng.", urgency: "week" },
  "tls.www-consistency": { today: "Một số khách gõ thiếu hoặc thừa “www” sẽ thấy lỗi hoặc vào bản kém an toàn.", worst: "Khách bị cảnh báo chứng chỉ hoặc chuyển sang bản không bảo vệ.", who: "Khách bình thường (gián đoạn); kẻ cùng mạng nếu bản đó là HTTP.", urgency: "later" },
  "adv.redirect-chain": { today: "Chuỗi chuyển hướng dài hoặc đi qua HTTP làm lộ lưu lượng ở bước trung gian và chậm khách.", worst: "Bị chặn hoặc đổi hướng ở bước đi qua HTTP.", who: "Kẻ tấn công cùng mạng.", urgency: "later" },
  "config.suspicious-redirects": { today: "Khách có thể bị chuyển tới website khác ngoài ý muốn bất cứ lúc nào.", worst: "Lừa đảo, chiếm lưu lượng, hoặc hạ cấp xuống HTTP.", who: "Bất kỳ khách nào truy cập." },
  "tls.insecure-login-form": { today: "Mỗi mật khẩu khách nhập hôm nay đều có thể đi qua đường truyền không an toàn.", worst: "Lộ mật khẩu hàng loạt của người dùng.", who: "Kẻ tấn công cùng mạng với khách.", urgency: "now" },
  "browser.form-targets": { today: "Mật khẩu khách nhập được gửi sang website khác. Nếu không có chủ đích thì đang bị đánh cắp ngay lúc này.", worst: "Đánh cắp thông tin đăng nhập hàng loạt (dấu hiệu mã bị chèn).", who: "Chủ website nhận dữ liệu; bất kỳ ai kiểm soát mã chèn vào.", urgency: "now" },
  "adv.form-method": { today: "Dữ liệu form nằm ngay trên URL, lưu vào lịch sử trình duyệt và nhật ký máy chủ.", worst: "Mật khẩu hoặc dữ liệu nhạy cảm lộ qua nhật ký, lịch sử và header Referer.", who: "Người dùng chung máy; bên có quyền đọc nhật ký.", urgency: "week" },
  "headers.csp": { today: "Không có gì xảy ra trừ khi website có lỗi chèn mã; CSP là lớp chặn thứ hai.", worst: "Một lỗi XSS nhỏ thành chiếm tài khoản hoặc đánh cắp dữ liệu vì không có gì chặn mã lạ.", who: "Kẻ tấn công phải tìm được lỗi chèn mã trước.", urgency: "week" },
  "adv.csp-analysis": { today: "CSP có nhưng còn chỗ hở nên vẫn có thể bị vượt qua nếu tìm được lỗi chèn mã.", worst: "Tác dụng gần như bằng không có CSP: mã chèn vào chạy tự do.", who: "Kẻ tìm được lỗi chèn mã.", urgency: "week" },
  "headers.frame-protection": { today: "Kẻ tấn công có thể nhúng trang của bạn vào trang của họ (clickjacking), nhưng cần dụ khách vào trang giả.", worst: "Khách bấm nút ẩn (đổi mật khẩu, xoá, chuyển tiền) mà không biết.", who: "Bất kỳ ai dụ được khách của bạn vào trang của họ.", urgency: "week" },
  "headers.x-content-type-options": { today: "Gần như không có gì xảy ra; chỉ nguy hiểm nếu website cho phép tải tệp lên.", worst: "Trình duyệt đoán sai loại tệp và chạy tệp tải lên như mã script (XSS).", who: "Cần một chỗ đưa được nội dung vào website.", urgency: "later" },
  "headers.broken": { today: "Header bị trình duyệt bỏ qua nên lớp bảo vệ bạn tưởng đang có thật ra không hoạt động.", worst: "Tin rằng đã được bảo vệ trong khi thực tế không.", who: "Tuỳ header sai: xem phần bằng chứng.", urgency: "week" },
  "headers.deprecated": { today: "Không có gì ngay; HPKP cũ có thể tự khoá khách khỏi website nếu cấu hình sai.", worst: "Website không truy cập được với khách đã nhận chính sách sai.", who: "Không cần kẻ tấn công.", urgency: "later" },
  "headers.cross-origin-isolation": { today: "Không có gì xảy ra ngay; đây là lớp tăng cường.", worst: "Rò rỉ dữ liệu qua tấn công kênh phụ giữa các trang trong cùng trình duyệt.", who: "Kẻ kiểm soát một trang khác mà khách đang mở.", urgency: "later" },
  "headers.cache-policy": { today: "Trang riêng tư có thể bị proxy hoặc CDN lưu và phát lại cho người khác.", worst: "Người lạ thấy nội dung hoặc phiên của người khác.", who: "Người dùng chung proxy hoặc CDN.", urgency: "week" },
  "adv.header-consistency": { today: "Một số trang thiếu header bảo vệ mà trang chủ có.", worst: "Kẻ tấn công nhắm đúng trang thiếu bảo vệ.", who: "Bất kỳ ai.", urgency: "week" },
  "adv.shared-cache-leak": { today: "Trang chứa phiên có thể bị CDN lưu và phát cho khách kế tiếp bất cứ lúc nào.", worst: "Lộ phiên đăng nhập của người này cho người khác.", who: "Bất kỳ khách nào truy cập sau.", urgency: "now" },
  "privacy.referrer-policy": { today: "Mỗi lần khách bấm ra ngoài, địa chỉ trang hiện tại (kể cả tham số) có thể gửi cho website kia.", worst: "Mã thông báo hoặc ID nhạy cảm nằm trong URL bị lộ cho bên thứ ba.", who: "Website hoặc quảng cáo mà khách bấm sang.", urgency: "later" },
  "privacy.permissions-policy": { today: "Hầu như không ảnh hưởng ngay; camera, micro vẫn do trình duyệt hỏi người dùng.", worst: "Mã bên thứ ba bị chèn có thể xin quyền camera hoặc vị trí qua trang của bạn.", who: "Cần có mã độc chạy được trên trang.", urgency: "later" },
  "cookies.flags": { today: "Nếu có lỗi XSS ở đâu đó hoặc khách dùng wifi công cộng, cookie phiên có thể bị lấy.", worst: "Chiếm tài khoản người dùng (session hijacking).", who: "Kẻ tấn công cần thêm điều kiện: lỗi XSS hoặc cùng mạng.", urgency: "week" },
  "cookies.prefix": { today: "Không có gì xảy ra ngay.", worst: "Tên miền con hoặc kênh HTTP ghi đè cookie phiên (cookie tossing).", who: "Kẻ kiểm soát một tên miền con.", urgency: "later" },
  "adv.cookie-scope": { today: "Cookie phiên được gửi tới cả tên miền con; một tên miền con yếu có thể đọc hoặc ghi đè nó.", worst: "Chiếm phiên qua tên miền con bị xâm nhập.", who: "Kẻ kiểm soát một tên miền con.", urgency: "week" },
  "browser.cors": { today: "Website lạ có thể đọc phản hồi của bạn từ trình duyệt khách. Nguy hiểm nếu có dữ liệu riêng hoặc đăng nhập.", worst: "Đọc dữ liệu tài khoản của khách đang đăng nhập từ một trang bất kỳ.", who: "Bất kỳ ai dụ được khách đang đăng nhập vào trang của họ." },
  "config.dns-email-security": { today: "Ai cũng có thể gửi email giả danh tên miền của bạn tới khách và đối tác ngay hôm nay (hiệu quả với nơi không kiểm tra).", worst: "Chiến dịch lừa đảo mạo danh công ty bạn: mất uy tín và tiền của khách.", who: "Bất kỳ ai trên Internet, không cần truy cập hệ thống của bạn.", urgency: "week" },
  "adv.spf-deep": { today: "Email giả danh dễ lọt, hoặc bản ghi lỗi khiến email thật bị loại.", worst: "Lừa đảo mạo danh hoặc email hợp lệ rơi vào thư rác.", who: "Bất kỳ ai gửi email.", urgency: "week" },
  "adv.dmarc-deep": { today: "Chính sách DMARC yếu nên thư giả mạo vẫn tới hộp thư người nhận.", worst: "Lừa đảo mạo danh tên miền của bạn.", who: "Bất kỳ ai trên Internet.", urgency: "week" },
  "config.server-disclosure": { today: "Bot quét tự động biết ngay phiên bản phần mềm để thử các lỗ hổng đã công bố.", worst: "Bị khai thác bằng lỗ hổng đã biết của đúng phiên bản nếu chưa vá.", who: "Bot quét hàng loạt.", urgency: "later" },
  "exposure.error-page-disclosure": { today: "Mỗi lần ai đó gây ra lỗi, họ thấy đường dẫn và cấu trúc nội bộ.", worst: "Lộ đường dẫn, phiên bản, đôi khi cả biến cấu hình, giúp tấn công có mục tiêu.", who: "Bất kỳ ai gây ra trang lỗi.", urgency: "week" },
  "exposure.html-comments": { today: "Ai bấm “Xem nguồn trang” đều đọc được ghi chú.", worst: "Lộ thông tin nội bộ hoặc thông tin đăng nhập bị bỏ quên trong ghi chú.", who: "Bất kỳ ai.", urgency: "later" },
  "exposure.internal-references": { today: "Kẻ tấn công biết thêm tên và địa chỉ hệ thống nội bộ để chuẩn bị.", worst: "Giúp lần theo mạng nội bộ nếu tìm được lỗi SSRF ở đâu đó.", who: "Bất kỳ ai xem mã trang.", urgency: "later" },
  "config.debug-headers": { today: "Header gỡ lỗi tiết lộ kiến trúc, đôi khi kèm liên kết tới trang debug chứa cấu hình.", worst: "Lộ cấu hình hoặc truy vấn cơ sở dữ liệu qua trang profiler.", who: "Bất kỳ ai." },
  "exposure.security-txt": { today: "Không có gì xảy ra với khách; người phát hiện lỗi thiện chí không biết báo cho ai.", worst: "Lỗ hổng được công bố công khai thay vì báo riêng cho bạn.", who: "Nhà nghiên cứu bảo mật.", urgency: "later" },
  "browser.mixed-content": { today: "Một số tài nguyên tải qua HTTP bị trình duyệt chặn, hoặc có thể bị kẻ cùng mạng thay thế.", worst: "Kẻ cùng mạng thay script hoặc ảnh tải qua HTTP để chạy mã trên trang.", who: "Kẻ tấn công cùng mạng.", urgency: "week" },
  "browser.third-party-integrity": { today: "Nếu nhà cung cấp CDN bị xâm nhập trong ngày, mã độc chạy ngay trên website của bạn.", worst: "Đánh cắp dữ liệu khách nhập (thẻ, mật khẩu) trên mọi trang tải script đó (supply chain).", who: "Kẻ xâm nhập được CDN hoặc nhà cung cấp.", urgency: "later" },
  "adv.supply-chain": { today: "Script bên thứ ba không ghim phiên bản: bản cập nhật độc hại sẽ chạy ngay trên website của bạn.", worst: "Đánh cắp dữ liệu hoặc thay đổi trang trên diện rộng.", who: "Kẻ xâm nhập được nhà cung cấp script.", urgency: "week" },
  "exposure.secrets": { today: "Khoá bí mật công khai coi như đã lộ: bot tự động quét và có thể dùng nó ngay trong ngày.", worst: "Bị lạm dụng dịch vụ (tốn tiền), lộ dữ liệu, chiếm hạ tầng.", who: "Bất kỳ ai hoặc bot tự động.", urgency: "now" },
  "exposure.public-config": { today: "Cấu hình công khai (Supabase, Firebase…) chỉ nguy hiểm nếu quy tắc truy cập (RLS/Rules) để hở.", worst: "Đọc hoặc ghi toàn bộ dữ liệu nếu quy tắc truy cập đang mở.", who: "Bất kỳ ai có khoá công khai.", urgency: "week" },
  "exposure.subdomain-takeover": { today: "Ai đăng ký được tài nguyên đang bỏ trống có thể chiếm tên miền con ngay.", worst: "Chạy nội dung lừa đảo hoặc đánh cắp cookie dưới tên miền của bạn.", who: "Bất kỳ ai.", urgency: "now" },
  "exposure.outdated-libraries": { today: "Thư viện có lỗ hổng đã công bố; bot có thể thử ngay nhưng cần điều kiện khai thác tuỳ lỗi.", worst: "XSS hoặc chiếm quyền qua lỗ hổng đã biết.", who: "Bot hoặc kẻ biết mã CVE.", urgency: "week" },
  "exposure.robots-txt": { today: "Không có gì xảy ra ngay; đường dẫn nhạy cảm liệt kê trong robots.txt gợi ý cho kẻ tấn công đi đâu.", worst: "Dẫn kẻ tấn công thẳng tới khu quản trị.", who: "Bất kỳ ai đọc robots.txt.", urgency: "later" },
  "exposure.sitemap-xml": { today: "Không có gì xảy ra ngay.", worst: "Liệt kê đường dẫn không định công khai.", who: "Bất kỳ ai.", urgency: "later" },
};

export const URGENCY_LABEL: Record<Urgency, string> = { now: "Sửa ngay hôm nay", week: "Sửa trong tuần này", later: "Sửa khi rảnh" };

export function urgencyFor(ruleId: string, severity: Severity | string): Urgency {
  const bySeverity: Urgency = severity === "critical" || severity === "high" ? "now" : severity === "medium" ? "week" : "later";
  const o = IMPACT[ruleId]?.urgency;
  // Ghi đè chỉ được NÂNG mức khẩn cấp hoặc hạ khi luật nói rõ; riêng mức Cao/Nghiêm trọng luôn là "ngay".
  if (bySeverity === "now") return "now";
  return o ?? bySeverity;
}
