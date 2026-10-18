# SECURITY-CONTENT-AUDIT — Kiểm toán nội dung giải thích bảo mật VibeSec

Ngày: 2026-10-17 · Nhánh: `phase-3.2-validation` · Người kiểm toán: Claude (Sonnet 5.5), rà soát độc lập trên mã nguồn
Phạm vi: nội dung giải thích, mức độ nghiêm trọng, hướng dẫn sửa, ví dụ và tài liệu tham khảo. **Không đổi logic phát hiện, điểm số hay benchmark.**

> **Lưu ý về số lượng:** yêu cầu nhắc tới “39 kiểm tra”, nhưng bộ luật hiện tại có **63 luật** (`ALL_RULES`, được khoá bởi `explain-quality.test.ts`): 48 luật cơ bản + 15 luật nâng cao `adv.*`. Báo cáo này kiểm toán **cả 63**. Con số 39 không khớp với bất kỳ cách đếm nào tôi tìm thấy trong repo (nếu đó là một tập con có chủ đích, hãy cho tôi biết để thu hẹp roadmap).

## 0. Tóm tắt điều hành

| Hạng mục | Kết quả |
|---|---|
| Luật có giải thích riêng (không fallback) | 63/63 (đã có từ đợt trước, nay được khoá thêm bằng test nhất quán) |
| Sai sót nội dung phát hiện và đã sửa | **3 sai về sự kiện**, 1 diễn đạt phóng đại, 2 luật thiếu mục “tác động” (xem §3) |
| Sai sót phát hiện nhưng **chưa sửa** (cần quyết định) | OWASP Top 10 **2021** và ASVS **4.0.3** đã bị thay thế bởi bản mới; 2 ứng viên “nâng mức nghiêm trọng” (xem §4) |
| Tầng “Đào sâu kỹ thuật” mới | **25** luật phổ biến/nguy hiểm nhất (CSP, HSTS, cookie, CORS, khoá bí mật, Supabase RLS, DNS/email…) |
| Ví dụ cấu hình được kiểm chứng tự động | Header mẫu được áp lên website mẫu và chạy lại **chính các luật quét**: không tạo phát hiện mới |
| Chưa làm (có chủ đích) | 38 luật còn lại chưa có tầng đào sâu → `REMEDIATION-CONTENT-ROADMAP.md` |

Điều **không** được tuyên bố: không website nào “an toàn tuyệt đối” vì điểm cao; không xếp hạng “5 giải thích khó hiểu nhất” khi chưa có dữ liệu người dùng thật (xem §6).

## 1. Phương pháp

1. **Kiểm kê tự động** bằng `scripts/content-inventory.ts` (bảng §2): đọc trực tiếp `ALL_RULES`, `STANDARDS`, `IMPACT`, `FIXES`, `FEYNMAN`, `PLAIN_TITLES`, `DEEP_DIVE`; mức nghiêm trọng trích tĩnh từ mã luật (gần đúng; “(động)” = quyết định lúc chạy).
2. **Đọc toàn bộ mẫu giải thích** (`explain.ts`, `explain-more.ts`), `impact.ts`, `remediation.ts`, `fixes.ts` và đối chiếu từng khẳng định kỹ thuật với tài liệu gốc (MDN, RFC, OWASP, CA/B Forum, tài liệu Next.js đi kèm trong `node_modules/next/dist/docs`, tài liệu Cloudflare/Supabase).
3. **Đối chiếu ánh xạ tiêu chuẩn** (CWE/ASVS/WSTG) theo ý nghĩa của từng kiểm tra.
4. **Kiểm thử**: `npm test` (1070 test), `npm run typecheck`, `npm run build` (OpenNext), và kiểm tra DOM trong trình duyệt (§7).

Giới hạn: chấm điểm dưới đây là **đánh giá của người rà soát**, không phải dữ liệu người dùng. Tôi không có kênh xác minh bên ngoài cho các hành vi của từng trình duyệt ngoài tài liệu đã nêu.

## 2. Kiểm kê 63 luật

Cột “Hình dung/Tác động/Fix/Đào sâu” = có nội dung ở tầng tương ứng (✓/—). “—” ở CWE/ASVS/WSTG nghĩa là luật mang tính thông tin hoặc chưa có yêu cầu chuẩn tương ứng rõ ràng (không phải thiếu sót).

| # | Luật | Nhóm | Mức nghiêm trọng (tĩnh) | CWE | ASVS | WSTG | Hình dung | Tác động | Fix theo nền tảng | Đào sâu |
|---|---|---|---|---|---|---|---|---|---|---|
| 1 | `tls.https-available` | Transport Security | high, info | 319 | 9.1.1 | WSTG-CRYP-03 | ✓ | ✓ | ✓ | — |
| 2 | `tls.certificate-expiry` | Transport Security | medium, low | 298 | 9.2.1 | WSTG-CRYP-01 | ✓ | ✓ | ✓ | ✓ |
| 3 | `tls.certificate-strength` | Transport Security | medium, low, info | 326 | 9.1.2 | WSTG-CRYP-01 | ✓ | ✓ | ✓ | — |
| 4 | `tls.protocol-version` | Transport Security | medium | 326 | 9.1.3 | WSTG-CRYP-01 | ✓ | ✓ | ✓ | ✓ |
| 5 | `tls.http2` | Transport Security | info | — | — | — | ✓ | ✓ | ✓ | — |
| 6 | `tls.http-to-https-redirect` | Transport Security | medium, info | 319 | 9.1.1 | WSTG-CONF-07 | ✓ | ✓ | ✓ | ✓ |
| 7 | `tls.www-consistency` | Transport Security | low, info | 319 | 9.1.1 | WSTG-CONF-07 | ✓ | ✓ | ✓ | — |
| 8 | `tls.hsts` | Transport Security | medium, low | 319 | 14.4.5 | WSTG-CONF-07 | ✓ | ✓ | ✓ | ✓ |
| 9 | `tls.insecure-login-form` | Transport Security | critical, high | 319 | 9.1.1 | WSTG-CRYP-03 | ✓ | ✓ | ✓ | — |
| 10 | `headers.csp` | Headers | (động) | 79 | 14.4.3 | WSTG-CONF-12 | ✓ | ✓ | ✓ | ✓ |
| 11 | `headers.frame-protection` | Headers | (động) | 1021 | 14.4.7 | WSTG-CLNT-09 | ✓ | ✓ | ✓ | ✓ |
| 12 | `headers.x-content-type-options` | Headers | low | 693 | 14.4.4 | WSTG-CONF-14 | ✓ | ✓ | ✓ | ✓ |
| 13 | `headers.broken` | Headers | info | 693 | 14.4.1 | WSTG-CONF-14 | ✓ | ✓ | ✓ | — |
| 14 | `headers.cross-origin-isolation` | Headers | (động) | 693 | — | WSTG-CONF-14 | ✓ | ✓ | ✓ | — |
| 15 | `headers.charset` | Headers | low | 116 | 14.4.1 | WSTG-CONF-14 | ✓ | ✓ | ✓ | — |
| 16 | `headers.deprecated` | Headers | (động) | 693 | 14.4.3 | WSTG-CONF-14 | ✓ | ✓ | ✓ | — |
| 17 | `browser.mixed-content` | Browser Security | medium, low | 319 | 9.1.1 | WSTG-CRYP-03 | ✓ | ✓ | ✓ | — |
| 18 | `browser.third-party-integrity` | Browser Security | low | 829 | 14.2.3 | — | ✓ | ✓ | ✓ | ✓ |
| 19 | `browser.cors` | Browser Security | low | 942 | 14.5.3 | WSTG-CLNT-07 | ✓ | ✓ | ✓ | ✓ |
| 20 | `cookies.flags` | Cookies & Sessions | (động) | 614, 1004, 1275 | 3.4.1, 3.4.2, 3.4.3 | WSTG-SESS-02 | ✓ | ✓ | ✓ | ✓ |
| 21 | `cookies.cache-control-sensitive` | Cookies & Sessions | (động) | 524 | 8.2.1 | WSTG-ATHN-06 | ✓ | ✓ | ✓ | — |
| 22 | `exposure.internal-references` | Exposure | low | 200 | — | WSTG-INFO-05 | ✓ | ✓ | ✓ | — |
| 23 | `exposure.html-comments` | Exposure | low | 615 | — | WSTG-INFO-05 | ✓ | ✓ | ✓ | — |
| 24 | `exposure.secrets` | Exposure | (động) | 798, 200 | 2.10.4 | WSTG-INFO-05 | ✓ | ✓ | ✓ | ✓ |
| 25 | `exposure.public-config` | Exposure | medium, info | 200 | — | WSTG-INFO-05 | ✓ | ✓ | ✓ | ✓ |
| 26 | `exposure.source-maps` | Exposure | medium | 540 | — | WSTG-INFO-05 | ✓ | ✓ | ✓ | ✓ |
| 27 | `exposure.robots-txt` | Exposure | info | 200 | — | WSTG-INFO-03 | ✓ | ✓ | ✓ | — |
| 28 | `exposure.sitemap-xml` | Exposure | info | — | — | WSTG-INFO-03 | ✓ | ✓ | ✓ | — |
| 29 | `exposure.security-txt` | Exposure | medium, low | — | — | — | ✓ | ✓ | ✓ | — |
| 30 | `exposure.outdated-libraries` | Exposure | (động) | 1104 | 14.2.1 | WSTG-INFO-08 | ✓ | ✓ | ✓ | — |
| 31 | `exposure.subdomain-takeover` | Exposure | high, medium, low | — | — | WSTG-CONF-10 | ✓ | ✓ | ✓ | ✓ |
| 32 | `exposure.error-page-disclosure` | Exposure | (động) | 209 | 7.4.1 | WSTG-ERRH-01 | ✓ | ✓ | ✓ | ✓ |
| 33 | `config.server-disclosure` | Configuration | low, info | 200 | 14.3.3 | WSTG-INFO-02 | ✓ | ✓ | ✓ | ✓ |
| 34 | `config.technology` | Configuration | info | — | — | WSTG-INFO-08 | ✓ | ✓ | — | — |
| 35 | `config.suspicious-redirects` | Configuration | medium, low, info | 601 | 5.1.5 | WSTG-CLNT-04 | ✓ | ✓ | ✓ | — |
| 36 | `config.dns-email-security` | Configuration | medium, low, info | — | — | — | ✓ | ✓ | ✓ | ✓ |
| 37 | `config.auth-surface` | Configuration | info | — | — | — | ✓ | ✓ | — | — |
| 38 | `privacy.referrer-policy` | Privacy | low | 200 | 14.4.6 | — | ✓ | ✓ | ✓ | ✓ |
| 39 | `privacy.permissions-policy` | Privacy | info | 693 | — | — | ✓ | ✓ | ✓ | ✓ |
| 40 | `privacy.third-party-origins` | Privacy | info | — | — | — | ✓ | ✓ | — | — |
| 41 | `privacy.trackers` | Privacy | info | — | — | — | ✓ | ✓ | — | — |
| 42 | `tls.hsts-preload` | Transport Security | low | 319 | 14.4.5 | WSTG-CONF-07 | ✓ | ✓ | ✓ | — |
| 43 | `tls.cipher-suite` | Transport Security | high | 327 | 9.1.2 | WSTG-CRYP-01 | ✓ | ✓ | ✓ | — |
| 44 | `headers.cache-policy` | Headers | medium, low | 524 | 8.2.1 | WSTG-ATHN-06 | ✓ | ✓ | ✓ | ✓ |
| 45 | `config.debug-headers` | Configuration | low | 215 | 14.3.2 | WSTG-CONF-02 | ✓ | ✓ | ✓ | — |
| 46 | `config.http-methods` | Configuration | medium, low | 749 | 14.5.1 | WSTG-CONF-06 | ✓ | ✓ | ✓ | ✓ |
| 47 | `browser.form-targets` | Browser Security | medium | 319 | 9.1.1 | WSTG-CRYP-03 | ✓ | ✓ | ✓ | — |
| 48 | `cookies.prefix` | Cookies & Sessions | low | 565 | 3.4.4 | WSTG-SESS-02 | ✓ | ✓ | ✓ | — |
| 49 | `adv.csp-analysis` | Headers (nâng cao) | (động) | 79 | 14.4.3 | WSTG-CONF-12 | ✓ | ✓ | ✓ | ✓ |
| 50 | `adv.shared-cache-leak` | Cookies & Sessions (nâng cao) | high, medium | 524, 525 | 8.2.1 | WSTG-ATHN-06 | ✓ | ✓ | ✓ | ✓ |
| 51 | `adv.cookie-scope` | Cookies & Sessions (nâng cao) | low | 613, 565 | 3.3.2, 3.4.5 | WSTG-SESS-02 | ✓ | ✓ | ✓ | — |
| 52 | `adv.supply-chain` | Browser Security (nâng cao) | (động) | 829, 494 | 14.2.3, 14.2.4 | — | ✓ | ✓ | ✓ | — |
| 53 | `adv.dom-xss-flow` | Browser Security (nâng cao) | medium | 79 | 5.3.3 | WSTG-CLNT-01 | ✓ | ✓ | ✓ | ✓ |
| 54 | `adv.postmessage` | Browser Security (nâng cao) | low | 346 | — | WSTG-CLNT-11 | ✓ | ✓ | ✓ | — |
| 55 | `adv.web-storage-secrets` | Browser Security (nâng cao) | low | 922 | — | WSTG-CLNT-12 | ✓ | ✓ | ✓ | ✓ |
| 56 | `adv.endpoint-map` | Exposure (nâng cao) | info | 200 | — | WSTG-INFO-06 | ✓ | ✓ | — | — |
| 57 | `adv.graphql-surface` | Exposure (nâng cao) | low | 200 | 13.4.1 | WSTG-APIT-01 | ✓ | ✓ | ✓ | — |
| 58 | `adv.redirect-chain` | Transport Security (nâng cao) | (động) | 319 | 9.1.1 | WSTG-CONF-07 | ✓ | ✓ | ✓ | — |
| 59 | `adv.header-consistency` | Headers (nâng cao) | (động) | 693 | 14.4.3, 14.4.4 | WSTG-CONF-14 | ✓ | ✓ | ✓ | — |
| 60 | `adv.spf-deep` | Configuration (nâng cao) | (động) | — | — | — | ✓ | ✓ | ✓ | — |
| 61 | `adv.dmarc-deep` | Configuration (nâng cao) | (động) | — | — | — | ✓ | ✓ | ✓ | — |
| 62 | `adv.certificate-hygiene` | Transport Security (nâng cao) | (động) | 295 | 9.2.1 | WSTG-CRYP-01 | ✓ | ✓ | ✓ | — |
| 63 | `adv.form-method` | Browser Security (nâng cao) | high | 598 | 8.3.1 | WSTG-CRYP-03 | ✓ | ✓ | ✓ | — |

Kết quả kiểm kê: mọi luật có tiêu đề dễ hiểu, hình dung đơn giản, mục tác động (sau khi bổ sung 2 luật thiếu) và mẫu giải thích riêng. Luật **không có** mẫu sửa theo nền tảng (`FIXES`): `config.technology`, `config.auth-surface`, `privacy.third-party-origins`, `privacy.trackers`, `adv.endpoint-map`. Cả năm đều là mục thông tin, nên không có thứ để “sửa”; chấp nhận được.

## 3. Sai sót đã phát hiện và đã sửa

| # | Vị trí | Vấn đề | Căn cứ | Sửa |
|---|---|---|---|---|
| F1 | `explain.ts` (`privacy.referrer-policy`), `impact.ts` | Nói “không có chính sách thì trình duyệt gửi **địa chỉ đầy đủ** cho website kế tiếp”. **Lỗi thời**: trình duyệt hiện đại mặc định `strict-origin-when-cross-origin` (khác origin chỉ gửi tên miền) | MDN + W3C Referrer Policy | Viết lại: nêu mặc định hiện đại, rủi ro chỉ còn với trình duyệt đời cũ; vẫn khuyến nghị đặt tường minh |
| F2 | `feynman.ts` (cùng luật) | Ví von “nói chính xác họ vừa mua gì” phóng đại so với thực tế | — | Viết lại trung tính |
| F3 | `transport.ts`, `advanced.ts`, `explain-more.ts` (`tls.certificate-strength|long-validity`, `adv.certificate-hygiene`) | Chỉ nêu mức tối đa **398 ngày**. Từ **15/3/2026** chứng chỉ công khai mới tối đa **200 ngày**, rồi 100 ngày (15/3/2027) và 47 ngày (15/3/2029) | CA/B Forum Ballot SC-081v3 (tổng hợp qua nhiều nguồn thứ cấp; nên đối chiếu văn bản ballot gốc khi trích dẫn chính thức) | Cập nhật lời giải thích và mục “sửa đúng thì”. **Ngưỡng phát hiện giữ nguyên 398 ngày** (chứng chỉ cấp trước đó vẫn hợp lệ tới khi hết hạn, và CA riêng không bị ràng buộc) |
| F4 | `fixes.ts` (`adv.csp-analysis`) | Hướng dẫn Next.js đặt nonce trong `middleware.ts`. Next.js 16 đổi sang **`proxy.ts`** (tài liệu đi kèm repo) | `node_modules/next/dist/docs/01-app/02-guides/content-security-policy.md` | Nhãn và chú thích nêu `proxy.ts` (tên cũ ở Next ≤15) |
| F5 | `impact.ts` | `config.technology` và `config.auth-surface` thiếu mục “Nếu để 1 ngày thì sao?” | Phát hiện nhờ test nhất quán mới | Bổ sung, viết thận trọng (mục thông tin) |

F1, F3, F4 được khoá bằng test hồi quy trong `deep-dive.test.ts` (nhóm “hồi quy các sai sót nội dung đã sửa”); F5 được khoá bởi test nhất quán giữa các tầng; F2 chỉ là sửa diễn đạt, không có test.

## 4. Phát hiện chưa sửa (cần quyết định của chủ sản phẩm)

| # | Vấn đề | Vì sao chưa sửa |
|---|---|---|
| O1 | **OWASP Top 10:2021** đang là khung tham chiếu (`standards.ts`, `guidance.ts`, bảng độ phủ). OWASP đã công bố **Top 10:2025** (A02 Security Misconfiguration, A03 Software Supply Chain Failures mới, A10 Mishandling of Exceptional Conditions mới; SSRF gộp vào A01). Mục “A10 SSRF — không thể thấy từ ngoài” trong bảng độ phủ vì thế lỗi thời | Đổi khung làm thay đổi bảng độ phủ, `OWASP_MAP` và test; cần bảng ánh xạ 2021→2025 được duyệt. Đề xuất ở roadmap P1 |
| O2 | **ASVS 4.0.3** (`ASVS_URL`, mã yêu cầu `14.4.x`…). ASVS 5.0.0 (công bố 2025) đánh số lại các yêu cầu. Nguồn tôi tìm được cho ngày phát hành là thứ cấp, cần xác nhận ở trang chính thức của ASVS trước khi trích | Cùng lý do O1. Mã yêu cầu trong UI vẫn đúng với 4.0.3 và được ghi rõ phiên bản |
| O3 | `exposure.source-maps` mức **medium** (độ tin cậy cao). Mã phía khách vốn đã công khai; source map chỉ làm dễ đọc hơn → nghiêng về **low** | Đổi mức nghiêm trọng đổi điểm số/benchmark; cần chạy lại benchmark độc lập |
| O4 | `adv.dom-xss-flow` mức **medium** nhưng độ tin cậy **thấp** (phân tích tĩnh, không chứng minh được luồng). Điểm số đã nhân hệ số độ tin cậy, nhưng nhãn “medium” vẫn dễ gây hiểu lầm | Như O3. Nội dung giải thích đã ghi “rủi ro tiềm năng / chưa đủ bằng chứng”, nên rủi ro hiểu lầm đã giảm |
| O5 | `wstgUrl()` tạo liên kết dạng `…/4-Web_Application_Security_Testing/#wstg-xxx-nn`. Tôi **chưa xác minh** các neo này dẫn đúng tới mục WSTG tương ứng | Cần kiểm tra tự động từng liên kết (có mạng) |
| O6 | `OWASP_MAP` không có khoá cho 10 luật (ví dụ `tls.http2`, `privacy.*`, `exposure.robots-txt`). Đây có thể là chủ ý (không thuộc hạng mục nào), nhưng chưa được ghi lại | Ghi chú trong roadmap |

## 5. Đánh giá chất lượng theo nhóm (đánh giá của người rà soát, thang 1–5)

| Nhóm luật | Chính xác kỹ thuật | Bối cảnh khai thác | Rõ ràng | Hữu ích khi sửa | Nguồn | Ghi chú |
|---|---|---|---|---|---|---|
| TLS/HSTS/chuyển hướng | 4 | 4 | 4 | 4 | 4 | Đã đúng sau F3; thiếu lưu ý lần-đầu-truy-cập cho HSTS (đã bổ sung ở tầng đào sâu) |
| Header (CSP, frame, nosniff…) | 5 | 4 | 4 | 4 | 4 | Phân biệt Report-Only, `strict-dynamic`, meta-CSP rất tốt; tránh false positive CSP đã sửa trước đó |
| Cookie/phiên | 4 | 4 | 4 | 4 | 4 | Tách “giống cookie phiên” (đoán từ tên) rõ ràng |
| CORS | 5 | 5 | 4 | 4 | 4 | Phân biệt phản chiếu/`null`/`*`/`*`+credentials đúng |
| Lộ thông tin & khoá bí mật | 4 | 4 | 4 | 4→5 | 4 | Nay có hướng dẫn xoay khoá, `NEXT_PUBLIC_`, Supabase `service_role` |
| Cấu hình/DNS/email | 4 | 3 | 4 | 4 | 3 | Không biết tên miền có gửi thư; đã nêu rõ ở tầng đào sâu |
| Quyền riêng tư | 3→4 | 3→4 | 4 | 4 | 4 | Sửa F1 |
| Luật nâng cao (`adv.*`) | 4 | 3 | 3 | 3 | 3 | Phân tích tĩnh, độ tin cậy thấp; đã gắn nhãn; chỉ 4/15 có tầng đào sâu |

Phát hiện **false positive / lạm phát mức độ / hướng dẫn lỗi thời**:
- False positive: không phát hiện thêm trong lần rà soát này (hai false positive CSP/`XSRF-TOKEN` đã được sửa ở `explanation-qa-report.md`).
- Nghi lạm phát mức độ: O3, O4.
- Lỗi thời: F1, F3, F4 (đã sửa); O1, O2 (chưa sửa).
- Quá chung chung: không còn (63/63 có mẫu riêng); tầng đào sâu bổ sung phần *vì sao sửa kiểu đó*, *lỗi hay mắc* và *đánh đổi*.

## 6. Cấu trúc nội dung mới

Mỗi phát hiện đi theo chuỗi **What → Why → Evidence → Risk → How to Fix → How to Verify** (đã có sẵn: `saw → why → consequence → steps/expect → verify`, kèm `certainty` + `caveat`). Bổ sung thêm **hai tầng**:

- **Tầng 1 — Giải thích cho người mới**: giữ nguyên (`explain*.ts`, `feynman.ts`).
- **Tầng 2 — Đào sâu kỹ thuật** (`deep-dive.ts`, hiển thị bằng `DeepDiveView`, thu gọn mặc định): **phân loại** (cấu hình sai đã quan sát / khuyến nghị thực hành tốt / dấu hiệu chưa đủ bằng chứng), cơ chế, ví dụ HTTP trước-sau, cấu hình theo nền tảng (Next.js, Vercel, Cloudflare Workers/CDN, Supabase, Nginx), lỗi thường gặp khi sửa, đánh đổi/tương thích, lệnh tự kiểm chứng **chỉ đọc**, nguồn chính thống.

Về yêu cầu “không tự xếp hạng 5 giải thích khó hiểu nhất khi chưa có dữ liệu thật”: không làm. Hạ tầng thu thập dữ liệu thật đã có (`/api/explain-feedback`, `/admin/giai-thich`, bộ khảo sát `docs/user-testing/`). Thứ tự ưu tiên viết lại phải xuất phát từ đó (cận dưới Wilson ≥ 30% “Chưa rõ”, n ≥ 10).

## 7. Kiểm chứng (Phase 4 — QA độc lập)

- **Cấu hình mẫu không tạo lỗi mới**: `deep-dive.test.ts` áp từng header mẫu (CSP đơn giản và CSP nonce/`strict-dynamic` theo tài liệu Next.js, HSTS có/không preload, Referrer-Policy, Permissions-Policy, nosniff, X-Frame-Options…) lên website mẫu đã cứng hoá rồi chạy **toàn bộ** luật: tập phát hiện lỗi phải bằng với website mẫu gốc. Ngoại lệ được khai báo tường minh: HSTS không có `preload` còn lại khuyến nghị `tls.hsts-preload` (đúng bản chất: preload là bước tuỳ chọn).
- **Chỉ-đọc**: test chặn lệnh kiểm chứng có `-X POST|PUT|DELETE|PATCH`, `rm`, `sudo`, `--data`.
- **Nhất quán**: mọi luật có đủ tiêu đề dễ hiểu / hình dung / tác động / mục tiêu chuẩn; không khoá mồ côi; không có cụm “an toàn tuyệt đối”.
- **Kết quả chạy**: `npm test` 44 file, **1070 test đạt** (trước: 43 file, 964); `npm run typecheck` sạch; `npm run build` (OpenNext) thành công; kiểm tra trình duyệt trên `/demo`: 4 mục có tầng đào sâu, không lỗi console; khi bấm “Kỹ thuật”, nội dung mở ra với phân loại, cơ chế và 9 khối mã.
- **Chưa kiểm chứng được**: không chạy các snippet Next.js/Workers trên một ứng dụng thật trong lần này (chỉ kiểm cú pháp bằng typecheck ở mức tổng thể repo, không phải trên snippet). Hành vi của từng phiên bản Cloudflare/Supabase có thể đổi; mỗi snippet kèm nguồn để đối chiếu.

## 8. Không ảnh hưởng production

Không thay đổi: logic phát hiện (`rules/*` chỉ đổi chuỗi văn bản ở 2 chỗ, không đổi điều kiện/mức độ), điểm số, quét, API feedback, admin. Phần thêm vào UI là một khối `<details>` thu gọn trong `Report.tsx`.

## 9. Phụ lục Phase 4 (cập nhật 2026-10-17)

- **Trùng lặp với PR #2:** một phiên khác đã tự sửa độc lập F1 (Referrer-Policy) và một phần F3 (hạn chứng chỉ) trong `phase-3.2-release-ready`. Khi xếp chồng PR #3 lên PR #2, giữ nguyên văn bản của #2 cho Referrer-Policy; giữ bản của #3 cho `long-validity` vì sửa đủ cả mục “Sửa đúng thì” (≤ 200 ngày) và giải thích CA riêng. Chi tiết: `PHASE4-RELEASE-READINESS.md` §1.
- **Sửa thêm sau khi đối chiếu tài liệu nền tảng:** CSP của Next.js cần `'unsafe-eval'` chỉ khi chạy dev; Vercel chỉ hỗ trợ TLS 1.2/1.3 và chuyển HTTP→HTTPS bằng 308; Supabase có khoá mới `sb_publishable_…` / `sb_secret_…` bên cạnh `anon` / `service_role`; bỏ lời khẳng định chưa kiểm chứng “Vercel đã tắt TLS 1.0/1.1 ở biên”.
- **O5 (liên kết WSTG):** trang gốc trả 200 nhưng các neo `#wstg-…` không phải thuộc tính `id` trên trang đó, nên liên kết đưa người đọc tới trang chỉ mục chứ không tới đúng bài kiểm tra. Đề xuất dùng URL riêng của từng bài kiểm tra.
- **59/59 URL nguồn** trong tầng đào sâu trả HTTP 200 (kiểm tra sự tồn tại, không kiểm tra nội dung khớp).
- **Số liệu tác động điểm số** của O3/O4 và kết quả xác thực snippet: xem `PHASE4-RELEASE-READINESS.md` §3–§4.
