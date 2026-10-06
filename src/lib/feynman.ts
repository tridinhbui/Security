/**
 * Chế độ Feynman: giải thích bằng phép so sánh đời thường, câu ngắn, không thuật ngữ — dành cho người không rành kỹ thuật.
 * Toàn bộ là văn bản viết sẵn (không dùng AI); chỉ phục vụ hiển thị, không ảnh hưởng logic phát hiện.
 * `like`: hình dung đơn giản. `todo`: việc cần làm, nói bằng ngôn ngữ thường.
 */
export interface Feynman { like: string; todo: string }

export const FEYNMAN: Record<string, Feynman> = {
  "tls.https-available": { like: "Như một cửa hàng không có cửa che: ai đi ngang cũng nhìn và nghe được mọi thứ khách nói với bạn.", todo: "Bật HTTPS (ổ khoá) cho website. Hầu hết nhà cung cấp hosting có nút bật miễn phí." },
  "tls.certificate-expiry": { like: "Như giấy phép kinh doanh sắp hết hạn: hết hạn là trình duyệt dán chữ “Không an toàn” lên cửa hàng của bạn.", todo: "Gia hạn chứng chỉ, hoặc bật tự động gia hạn để khỏi phải nhớ." },
  "tls.certificate-strength": { like: "Như ổ khoá có chìa quá đơn giản: kẻ xấu thử vài lần là mở được.", todo: "Nhờ nơi cấp chứng chỉ đổi sang loại khoá mạnh hơn (thường chỉ là một lựa chọn khi tạo lại)." },
  "tls.protocol-version": { like: "Như vẫn dùng loại khoá cũ đã bị nhà sản xuất khuyến cáo bỏ vì dễ bị phá.", todo: "Tắt các phiên bản mã hoá cũ trong cấu hình máy chủ hoặc nhờ nhà cung cấp hosting làm giúp." },
  "tls.http2": { like: "Như mở thêm nhiều quầy thanh toán cùng lúc để khách đỡ phải xếp hàng, trang tải nhanh hơn.", todo: "Bật HTTP/2 — thường chỉ là một công tắc trong cài đặt hosting. Không gấp." },
  "tls.http-to-https-redirect": { like: "Như khách đi cửa sau không có bảo vệ, trong khi cửa trước có. Bạn cần chỉ họ sang cửa trước.", todo: "Bật “tự động chuyển HTTP sang HTTPS” trong cài đặt hosting." },
  "tls.www-consistency": { like: "Như cửa hàng có hai địa chỉ: một bên có bảo vệ, một bên thì không.", todo: "Làm cho cả “có www” và “không www” đều dẫn tới phiên bản an toàn." },
  "tls.hsts": { like: "Như dán biển “Chỉ vào bằng cửa trước có bảo vệ” để trình duyệt nhớ, không đi đường tắt nguy hiểm.", todo: "Thêm một dòng cấu hình HSTS. Dùng đoạn lệnh bên dưới." },
  "tls.hsts-preload": { like: "Như đăng ký vào danh sách “luôn đi cửa an toàn” mà mọi trình duyệt có sẵn, ngay từ lần ghé đầu tiên.", todo: "Không gấp. Chỉ làm khi bạn chắc chắn website luôn dùng HTTPS." },
  "tls.cipher-suite": { like: "Như chọn kiểu khoá cho cửa: có kiểu hiện đại rất chắc, có kiểu cũ dễ bị phá.", todo: "Nhờ người quản lý máy chủ bật kiểu mã hoá hiện đại (hosting lớn thường đã tự có)." },
  "tls.insecure-login-form": { like: "Như khách đưa chìa khoá nhà qua cửa sổ mở toang trên đường phố.", todo: "Đảm bảo trang đăng nhập chạy trên HTTPS. Đây là việc nên làm sớm." },
  "headers.csp": { like: "Như danh sách khách mời: chỉ những nơi bạn tin tưởng mới được đưa mã vào trang. Người lạ bị chặn ở cửa.", todo: "Bắt đầu bằng chế độ thử (chỉ báo cáo, chưa chặn). Dùng đoạn lệnh bên dưới rồi theo dõi." },
  "headers.frame-protection": { like: "Như kẻ gian dựng một tấm kính trong suốt phủ lên trang của bạn, khách tưởng bấm nút này nhưng thật ra bấm nút khác.", todo: "Thêm một dòng cấu hình để cấm website khác nhúng trang của bạn." },
  "headers.x-content-type-options": { like: "Như bắt nhân viên đọc đúng nhãn ghi trên hộp, đừng tự đoán bên trong là gì.", todo: "Thêm một dòng cấu hình “nosniff”. Một phút là xong." },
  "headers.broken": { like: "Như có biển báo an toàn nhưng viết sai chính tả nên không ai hiểu, coi như không có.", todo: "Sửa lỗi gõ trong cấu hình theo hướng dẫn bên dưới." },
  "headers.cross-origin-isolation": { like: "Như đặt các phòng trong toà nhà vào các khoang riêng, sự cố ở phòng này không lan sang phòng khác.", todo: "Không gấp. Chỉ cần nếu website xử lý dữ liệu rất nhạy cảm." },
  "headers.charset": { like: "Như không ghi rõ tài liệu viết bằng ngôn ngữ nào nên chữ có thể bị hiển thị sai.", todo: "Thêm khai báo bảng mã UTF-8. Rất nhanh." },
  "headers.deprecated": { like: "Như vẫn dán biển báo kiểu cũ mà luật mới đã bỏ, không giúp gì mà còn gây hiểu nhầm.", todo: "Xoá cấu hình lỗi thời, thay bằng cấu hình mới theo hướng dẫn." },
  "headers.cache-policy": { like: "Như để bản sao hoá đơn của khách này trên quầy cho khách sau thấy.", todo: "Thêm quy tắc không lưu đệm cho trang chứa thông tin riêng." },
  "browser.mixed-content": { like: "Như cửa hàng có khoá chắc chắn nhưng lại nhận hàng qua một cửa sổ để ngỏ.", todo: "Đổi mọi đường dẫn http:// trong trang thành https://." },
  "browser.third-party-integrity": { like: "Như nhận hàng từ nhà cung cấp bên ngoài mà không kiểm tra niêm phong. Lỡ ai đó đánh tráo, bạn không biết.", todo: "Thêm “dấu niêm phong” (integrity) cho các script bên ngoài, hoặc tự lưu bản sao." },
  "browser.cors": { like: "Như cho mọi người lạ vào đọc sổ sách của bạn vì quên ghi rõ ai được phép.", todo: "Giới hạn chỉ các website bạn tin tưởng mới được đọc dữ liệu." },
  "browser.form-targets": { like: "Như điền đơn xin việc nhưng đơn lại được gửi tới một địa chỉ lạ.", todo: "Kiểm tra form có gửi dữ liệu về đúng website của bạn, qua HTTPS." },
  "cookies.flags": { like: "Như vé gửi xe không có hình in: ai nhặt được cũng lấy được xe.", todo: "Bật các cờ bảo vệ cookie (Secure, HttpOnly, SameSite) bằng đoạn lệnh bên dưới." },
  "cookies.prefix": { like: "Như vé có tem chống giả, kẻ gian khó làm vé giả đè lên vé thật.", todo: "Đổi tên cookie đăng nhập theo hướng dẫn. Cần thử kỹ trước khi áp dụng." },
  "cookies.cache-control-sensitive": { like: "Như để trang chứa thông tin riêng trên bàn công cộng sau khi dùng xong.", todo: "Thêm quy tắc không lưu đệm cho các trang riêng tư." },
  "exposure.secrets": { like: "Như viết mật khẩu két sắt lên cửa tiệm, ai đi qua cũng đọc được.", todo: "Đổi ngay khoá bí mật đó (coi như đã lộ), rồi gỡ khỏi mã trang. Đây là việc khẩn cấp." },
  "exposure.public-config": { like: "Như dán cả bảng cài đặt nội bộ lên cửa, trong đó có thể chứa thứ không nên cho người ngoài biết.", todo: "Xem lại các thiết lập đang lộ, chuyển phần nhạy cảm sang phía máy chủ." },
  "exposure.source-maps": { like: "Như vứt bản vẽ gốc của toà nhà ngay trước cửa, kẻ gian dễ tìm chỗ yếu.", todo: "Tắt việc xuất bản source map ở bản chạy thật." },
  "exposure.robots-txt": { like: "Như tấm bảng “khu vực này đừng vào” nhưng lại ghi luôn khu vực quan trọng ở đâu.", todo: "Rà lại tệp, đừng liệt kê đường dẫn nhạy cảm vào đó." },
  "exposure.sitemap-xml": { like: "Như tấm bản đồ chỉ đường cho công cụ tìm kiếm. Có thì tốt cho việc được tìm thấy.", todo: "Không gấp. Tạo sitemap nếu bạn muốn được tìm thấy trên Google." },
  "exposure.security-txt": { like: "Như số điện thoại đường dây nóng: người phát hiện lỗi sẽ biết gọi cho ai.", todo: "Thêm một tệp nhỏ ghi email liên hệ bảo mật. Năm phút là xong." },
  "exposure.outdated-libraries": { like: "Như dùng loại khoá đã bị nhà sản xuất thu hồi vì phát hiện cách phá khoá.", todo: "Cập nhật thư viện lên bản mới, rồi thử lại website." },
  "exposure.subdomain-takeover": { like: "Như bỏ trống một cửa hàng nhưng vẫn treo bảng hiệu của bạn. Người lạ vào mở tiệm dưới tên bạn.", todo: "Xoá tên miền phụ không còn dùng, hoặc trỏ lại đúng dịch vụ." },
  "exposure.error-page-disclosure": { like: "Như nhân viên khi gặp sự cố lại đọc to bản vẽ nội bộ của cửa hàng cho khách nghe.", todo: "Đổi sang trang lỗi chung chung, ghi chi tiết vào nhật ký nội bộ." },
  "exposure.internal-references": { like: "Như để lại sơ đồ nội bộ công ty trên bàn tiếp khách.", todo: "Xoá các địa chỉ và tên máy nội bộ khỏi mã trang." },
  "exposure.html-comments": { like: "Như quên gỡ giấy ghi chú “mật khẩu là…” dán trong cửa hàng.", todo: "Xoá ghi chú của lập trình viên khỏi bản chạy thật." },
  "config.server-disclosure": { like: "Như treo biển “Cửa này dùng khoá hãng X, đời Y”: kẻ gian biết ngay cách phá.", todo: "Ẩn thông tin phiên bản máy chủ trong cấu hình." },
  "config.technology": { like: "Chỉ là ghi chú: website của bạn đang xây bằng công nghệ nào, ai tò mò cũng đoán được.", todo: "Không cần làm gì. Chỉ cần luôn cập nhật công nghệ đó." },
  "config.suspicious-redirects": { like: "Như khách đi vào cửa hàng của bạn nhưng bị dắt sang một con phố lạ.", todo: "Kiểm tra các đường chuyển hướng, chỉ cho phép đích đến bạn tin tưởng." },
  "config.dns-email-security": { like: "Như ai cũng in được danh thiếp mang tên công ty bạn. Họ có thể gửi email giả danh bạn.", todo: "Thêm các bản ghi SPF và DMARC cho tên miền. Dùng đoạn lệnh bên dưới." },
  "config.auth-surface": { like: "Chỉ là quan sát: nhìn từ ngoài, người ta thấy cửa đăng nhập của bạn ở đâu và trông thế nào.", todo: "Không cần làm gì gấp. Hãy bật xác thực hai lớp nếu có thể." },
  "config.debug-headers": { like: "Như nhân viên quên tắt máy ghi âm nội bộ, thông tin gỡ lỗi lọt ra ngoài.", todo: "Tắt chế độ gỡ lỗi ở bản chạy thật." },
  "config.http-methods": { like: "Như để mở cả những cánh cửa phụ bạn không bao giờ dùng.", todo: "Đóng các thao tác không cần thiết trong cấu hình máy chủ." },
  "privacy.referrer-policy": { like: "Như khách rời tiệm và nói với tiệm kế bên chính xác họ vừa mua gì ở chỗ bạn.", todo: "Thêm một dòng cấu hình để giới hạn thông tin “vừa từ đâu tới”." },
  "privacy.permissions-policy": { like: "Như khoá sẵn phòng camera và micro, trừ khi thật sự cần.", todo: "Thêm một dòng cấu hình khoá camera, micro, vị trí nếu bạn không dùng." },
  "privacy.third-party-origins": { like: "Như có nhiều người lạ đứng trong tiệm quan sát khách của bạn.", todo: "Rà lại các dịch vụ bên ngoài, bỏ cái nào không còn cần." },
  "privacy.trackers": { like: "Như có người theo sau khách trong tiệm để ghi lại họ xem gì.", todo: "Nếu có theo dõi, hãy nói rõ trong chính sách riêng tư, hoặc gỡ bớt." },
};

/** Lời giải thích điểm số bằng ngôn ngữ thường. */
export function plainScore(score: number, issues: number, urgent: number): string {
  if (urgent > 0) return `Điểm ${score}/100. Có ${urgent} việc nên làm ngay, giống như cửa nhà còn hở. Xử lý chúng trước.`;
  if (issues === 0) return `Điểm ${score}/100. Chưa thấy điểm yếu nào đáng kể từ bên ngoài. Tốt lắm, nhưng hãy quét lại định kỳ.`;
  if (score >= 80) return `Điểm ${score}/100. Khá ổn. Còn ${issues} chỗ nhỏ có thể làm chắc thêm, không gấp.`;
  if (score >= 60) return `Điểm ${score}/100. Tạm ổn nhưng còn ${issues} chỗ yếu. Nên sửa dần trong tuần này.`;
  return `Điểm ${score}/100. Còn khá nhiều chỗ yếu (${issues}). Hãy làm từ việc đầu danh sách trở xuống.`;
}

export const PLAIN_SEV: Record<string, string> = {
  critical: "Rất nguy hiểm, sửa ngay", high: "Nguy hiểm, nên sửa sớm", medium: "Đáng lưu ý", low: "Nhẹ, sửa khi rảnh", info: "Chỉ để biết",
};
