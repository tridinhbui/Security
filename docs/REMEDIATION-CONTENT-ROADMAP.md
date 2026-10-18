# REMEDIATION-CONTENT-ROADMAP — Lộ trình nội dung khắc phục

Ngày: 2026-10-17 · Liên quan: [`SECURITY-CONTENT-AUDIT.md`](SECURITY-CONTENT-AUDIT.md)

Mục tiêu: người không biết bảo mật vẫn **hiểu** lỗi, **biết sửa** và **tự xác minh** đã sửa đúng. Nguyên tắc: không đổi logic phát hiện nếu không có bằng chứng bug và test độc lập; không tuyên bố an toàn tuyệt đối; thứ tự ưu tiên viết lại dựa trên **dữ liệu người dùng thật**, không dựa trên phán đoán của người viết.

## 1. Đã hoàn thành trong đợt này

- Tầng 2 “Đào sâu kỹ thuật” cho **25 luật** (xem `src/lib/scanner/deep-dive.ts`): `headers.csp`, `adv.csp-analysis`, `tls.hsts`, `tls.http-to-https-redirect`, `tls.protocol-version`, `tls.certificate-expiry`, `cookies.flags`, `browser.cors`, `headers.frame-protection`, `headers.x-content-type-options`, `privacy.referrer-policy`, `privacy.permissions-policy`, `config.server-disclosure`, `exposure.secrets`, `exposure.public-config` (Supabase RLS), `exposure.source-maps`, `exposure.error-page-disclosure`, `browser.third-party-integrity`, `adv.web-storage-secrets`, `adv.dom-xss-flow`, `headers.cache-policy`, `adv.shared-cache-leak`, `config.dns-email-security`, `exposure.subdomain-takeover`, `config.http-methods`.
- Sửa 3 sai sót sự kiện (Referrer-Policy mặc định, hạn chứng chỉ 200 ngày, `proxy.ts` của Next.js 16) và bổ sung mục tác động cho 2 luật.
- Test nhất quán nội dung giữa các tầng và test xác minh cấu hình mẫu.

## 2. Việc cần quyết định (không tự làm vì đổi hành vi hiển thị/điểm số)

| Ưu tiên | Việc | Lý do | Điều kiện hoàn thành |
|---|---|---|---|
| P1 | Chuyển khung tham chiếu sang **OWASP Top 10:2025** (giữ bảng 2021→2025) và cập nhật mục “A10 SSRF” trong bảng độ phủ | Top 10:2021 đã bị thay thế; SSRF nay nằm ở A01, có hạng mục mới về chuỗi cung ứng và xử lý ngoại lệ | Bảng ánh xạ 63 luật được người có chuyên môn duyệt; test `owaspCoverage` cập nhật |
| P1 | Xác nhận ngày phát hành và đánh số của **ASVS 5.0** ở trang chính thức, rồi lập bảng ánh xạ 4.0.3→5.0 | Mã yêu cầu `14.4.x` sẽ sai so với bản hiện hành | Mỗi mã trong `STANDARDS` có chú thích phiên bản |
| P2 | Xem lại mức nghiêm trọng của `exposure.source-maps` (medium) và `adv.dom-xss-flow` (medium, độ tin cậy thấp) | Nghi lạm phát mức độ | Chạy lại benchmark độc lập; ghi rõ ảnh hưởng điểm số trước khi đổi |
| P2 | Kiểm tra tự động liên kết `wstgUrl()` (neo `#wstg-…`) | Chưa xác minh | Báo cáo liên kết hỏng bằng script có mạng |
| P3 | Ghi chú lý do 10 luật không có trong `OWASP_MAP` | Có thể chủ ý, chưa được ghi lại | Chú thích trong `guidance.ts` |

## 3. Phủ nốt tầng đào sâu cho 38 luật còn lại

Thứ tự đề xuất theo (mức phổ biến × mức nguy hiểm khi sửa sai), **sẽ được điều chỉnh bằng dữ liệu `/admin/giai-thich`** khi mỗi biến thể có n ≥ 10:

| Đợt | Luật | Nội dung cần có (ngoài khung chung) |
|---|---|---|
| A | `tls.https-available`, `tls.insecure-login-form`, `browser.form-targets`, `adv.form-method`, `browser.mixed-content` | Phân biệt “không có HTTPS” và “chứng chỉ không tin cậy”; ví dụ form POST qua HTTPS; kiểm tra `upgrade-insecure-requests` |
| B | `cookies.prefix`, `adv.cookie-scope`, `cookies.cache-control-sensitive`, `config.debug-headers`, `exposure.outdated-libraries`, `adv.supply-chain` | `__Host-` và phạm vi `Domain`; cách quản lý phụ thuộc (npm audit, Dependabot); ví dụ SRI + ghim phiên bản |
| C | `adv.spf-deep`, `adv.dmarc-deep`, `tls.hsts-preload`, `tls.cipher-suite`, `tls.certificate-strength`, `adv.certificate-hygiene` | Quy trình nâng DMARC theo giai đoạn; cấu hình cipher theo Mozilla “Intermediate”; lưu ý kế hoạch chứng chỉ 100 ngày (3/2027) và 47 ngày (3/2029) |
| D | `adv.postmessage`, `adv.graphql-surface`, `adv.endpoint-map`, `config.suspicious-redirects`, `adv.redirect-chain`, `tls.www-consistency` | Kiểm tra `event.origin`; tắt introspection ở production kèm giới hạn độ sâu truy vấn; chống open redirect bằng danh sách cho phép |
| E | `headers.broken`, `headers.deprecated`, `headers.charset`, `headers.cross-origin-isolation`, `adv.header-consistency`, `exposure.security-txt`, `exposure.robots-txt`, `exposure.sitemap-xml`, `exposure.html-comments`, `exposure.internal-references`, `config.technology`, `config.auth-surface`, `privacy.third-party-origins`, `privacy.trackers`, `tls.http2` | Phần lớn là best-practice hoặc thông tin: ưu tiên làm rõ “đây không phải lỗ hổng” hơn là cấu hình |

Tiêu chí hoàn thành mỗi luật (đã được test khoá): phân loại `kind`; cơ chế; ví dụ HTTP trước/sau (nếu áp dụng); ít nhất 2 lỗi thường gặp khi sửa; ít nhất 1 đánh đổi/tương thích; lệnh kiểm chứng chỉ đọc; ≥ 2 nguồn chính thống; ví dụ header mẫu phải qua test “không tạo lỗi mới”.

## 4. Mở rộng nền tảng

| Việc | Ghi chú |
|---|---|
| Thêm Apache, Express, Caddy, Netlify, Nginx cho các snippet header | `remediation.ts` đã có Nginx/Apache/Express cho header; tầng đào sâu hiện ưu tiên Next.js / Vercel / Cloudflare / Supabase theo yêu cầu |
| Kiểm chạy snippet trên ứng dụng thật (Next.js 16 + OpenNext/Workers, Vercel, Supabase) | Đợt này chỉ kiểm bằng test cấu hình mẫu trên bộ luật quét; cần kiểm trên triển khai thật. Lưu ý: tệp `_headers` của Workers chỉ áp cho tài nguyên tĩnh, không áp cho phản hồi do mã Worker/Next tạo |
| Danh sách kiểm tra (checklist) cho người không chuyên | Dựng từ `EFFORT` + `IMPACT` + tầng đào sâu: “làm trong 1 giờ / 1 tuần / theo kế hoạch”, kèm mục “tự xác minh” |
| Vòng đời nội dung | Rà soát nội dung khi: trình duyệt đổi mặc định (Referrer-Policy, SameSite), CA/B Forum đổi thời hạn chứng chỉ (15/3/2027: 100 ngày), Next.js đổi API (tên `proxy.ts`), OWASP phát hành bản mới |

## 5. Đo hiệu quả (thay vì phán đoán)

1. Dùng bộ khảo sát `docs/user-testing/` với người **không** chuyên bảo mật; ghi vào `observations.csv`, tổng hợp bằng `scripts/usertest-summary.ts`.
2. Dùng bình chọn “Giải thích này có rõ không?” (`/api/explain-feedback`); chỉ xếp “cần viết lại” khi cận dưới Wilson 95% của tỉ lệ “Chưa” ≥ 30% và n ≥ 10.
3. Chỉ sau khi có dữ liệu mới xếp hạng các giải thích khó hiểu nhất và viết lại theo thứ tự đó.
4. Đo thêm: tỉ lệ người quét lại sau khi sửa và vấn đề đã được giải quyết (số `resolved` giữa hai lần quét liên tiếp cùng website).
