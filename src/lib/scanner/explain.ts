import type { Finding } from "./types";
import { IMPACT } from "./impact";
import { reproFor } from "./analyst";
import { T2, type Certainty } from "./explain-more";

/**
 * GIẢI THÍCH THEO TỪNG TRƯỜNG HỢP CỤ THỂ (không AI, không văn bản chung theo nhóm).
 * Mỗi phát hiện được diễn giải qua 4 câu trả lời cho ĐÚNG website này:
 *   saw         — chúng tôi thấy gì (tên header / giá trị / địa chỉ thật);
 *   why         — vì sao đó là vấn đề (cơ chế nối bằng chứng với rủi ro);
 *   consequence — hệ quả cụ thể;
 *   steps       — làm gì, ai làm, và kết quả đúng trông thế nào.
 * Cộng với `notes`: lời đọc cho từng dòng bằng chứng ("dòng này nghĩa là gì và vì sao chứng minh lỗi").
 * Luật chưa có mẫu riêng vẫn nhận phần diễn giải dựng từ summary/bằng chứng thật (không bao giờ là câu chung của cả luật).
 */
export type Role = "dev" | "host" | "dns" | "owner";
export const ROLE_LABEL: Record<Role, string> = { dev: "Lập trình viên", host: "Quản trị hosting / CDN", dns: "Người quản lý tên miền (DNS)", owner: "Chủ website" };
export interface Step { who: Role; text: string }
export interface Explanation {
  saw: string; why: string; consequence: string; steps: Step[]; expect: string;
  notes: { line: string; note: string }[];
  /** true nếu dùng mẫu viết riêng cho luật/biến thể này; false = dựng từ dữ liệu của phát hiện. */
  specific: boolean;
  /** Mức chắc chắn của kết luận: confirmed = đã quan sát đúng điều nêu; potential = rủi ro tuỳ ngữ cảnh/suy ra; inconclusive = thiếu dữ liệu. */
  certainty: Certainty;
  /** Giới hạn của bằng chứng (vd. chỉ là cấu hình, chưa chứng minh khai thác được). */
  caveat: string;
  /** Lệnh CHỈ ĐỌC để kiểm tra lại sau khi sửa. */
  verify: string;
}

const q = (s: string) => `“${s}”`;
const clip = (s: string, n = 140) => (s.length > n ? `${s.slice(0, n - 1)}…` : s);
/** Giá trị của một dòng bằng chứng dạng `tên: giá trị` (undefined nếu không có hoặc ghi "(không có)"). */
function ev(f: Finding, name: string): string | undefined {
  const re = new RegExp(`^${name}\\s*:\\s*(.*)$`, "i");
  for (const l of f.evidence) { const m = re.exec(l.trim()); if (m) return /^\(không có\)$/i.test(m[1]!) ? undefined : m[1]!.trim(); }
  return undefined;
}
const key = (f: Finding) => f.fingerprint.split("|")[1] ?? "";

type Tpl = (f: Finding, host: string) => Partial<Omit<Explanation, "specific">> & { note?: (line: string) => string | undefined } | null;

const T: Record<string, Tpl> = {
  "headers.broken": (f) => {
    const k = key(f);
    const h = (n: string) => ev(f, n) ?? "";
    switch (k) {
      case "xfo": return { saw: `Header X-Frame-Options đang có giá trị ${q(h("x-frame-options"))}.`, why: "Trình duyệt chỉ chấp nhận hai giá trị là DENY hoặc SAMEORIGIN. “ALLOW-FROM” và các giá trị khác đã bị loại khỏi chuẩn, nên trình duyệt bỏ qua cả dòng này.", consequence: "Dòng header tồn tại nhưng không bảo vệ gì: trang vẫn có thể bị nhúng vào website khác để dụ khách bấm nhầm (clickjacking), dù bạn tưởng đã chặn.", steps: [{ who: "host", text: "Đổi giá trị thành DENY (không cho ai nhúng) hoặc SAMEORIGIN (chỉ website của bạn được nhúng)." }, { who: "dev", text: "Muốn cho phép đúng một nguồn nhúng thì dùng CSP: frame-ancestors https://nguon-duoc-phep.com." }], expect: "Header trả về X-Frame-Options: DENY (hoặc SAMEORIGIN).", note: (l) => /x-frame-options/i.test(l) ? "Đây là giá trị server đang gửi. Giá trị này không nằm trong danh sách trình duyệt chấp nhận (DENY, SAMEORIGIN), nên bị bỏ qua." : undefined };
      case "xcto": return { saw: `Header X-Content-Type-Options đang là ${q(h("x-content-type-options"))}.`, why: "Giá trị hợp lệ duy nhất là “nosniff”. Giá trị khác thì trình duyệt coi như không có header này.", consequence: "Trình duyệt vẫn tự đoán loại nội dung của tệp; một tệp tải lên có thể bị chạy như mã script.", steps: [{ who: "host", text: "Đặt đúng X-Content-Type-Options: nosniff." }], expect: "Header trả về X-Content-Type-Options: nosniff.", note: (l) => /x-content-type-options/i.test(l) ? "Giá trị server gửi. Chỉ “nosniff” có tác dụng; giá trị này bị bỏ qua." : undefined };
      case "hsts-no-maxage": return { saw: `Header Strict-Transport-Security chỉ có ${q(h("strict-transport-security"))} mà không có max-age.`, why: "max-age cho trình duyệt biết phải nhớ quy tắc “luôn dùng HTTPS” trong bao lâu. Thiếu max-age, trình duyệt bỏ qua cả header.", consequence: "Website thực tế KHÔNG được bảo vệ bởi HSTS, dù bạn đã cấu hình. Request đầu tiên của khách vẫn có thể đi qua http:// không mã hoá.", steps: [{ who: "host", text: "Đặt Strict-Transport-Security: max-age=63072000; includeSubDomains." }], expect: "Header có max-age lớn hơn 0 (nên là 63072000, tức 2 năm).", note: (l) => /strict-transport-security/i.test(l) ? "Header có mặt nhưng thiếu max-age nên không có hiệu lực." : undefined };
      case "hsts-zero": return { saw: "Header Strict-Transport-Security có max-age=0.", why: "max-age=0 yêu cầu trình duyệt QUÊN quy tắc chỉ dùng HTTPS đã lưu trước đó.", consequence: "HSTS bị tắt chủ động: khách lần sau quay lại không còn được ép dùng HTTPS.", steps: [{ who: "host", text: "Nếu không có lý do cần tắt, đặt max-age=63072000; includeSubDomains." }], expect: "max-age lớn hơn 0.", note: (l) => /strict-transport-security/i.test(l) ? "max-age=0: trình duyệt xoá quy tắc HSTS đang nhớ." : undefined };
      case "csp-unquoted": {
        const kw = /“?"?([a-z-]+)"? phải viết/i.exec(f.summary)?.[1] ?? "self";
        return { saw: `CSP dùng từ khoá ${q(kw)} không có dấu nháy đơn.`, why: `Trong CSP, từ khoá phải viết '${kw}' (có dấu nháy đơn). Không có nháy, trình duyệt hiểu ${q(kw)} là TÊN MỘT WEBSITE tên như vậy chứ không phải từ khoá.`, consequence: "Chính sách không hoạt động như bạn định: nguồn bạn muốn cho phép (chính website mình) thực tế không được cho phép, hoặc bộ lọc để hở ngoài ý muốn.", steps: [{ who: "dev", text: `Sửa thành '${kw}' (kèm dấu nháy đơn) trong giá trị Content-Security-Policy.` }, { who: "dev", text: "Thử ở chế độ Content-Security-Policy-Report-Only trước khi bật chính thức." }], expect: `CSP chứa '${kw}' có dấu nháy đơn.`, note: (l) => /content-security-policy/i.test(l) ? `Chính sách đang gửi. Từ ${q(kw)} ở đây thiếu dấu nháy đơn.` : undefined };
      }
      case "csp-meta-ignored": return { saw: "CSP được đặt qua thẻ <meta> nhưng chứa frame-ancestors, report-uri hoặc sandbox.", why: "Khi CSP đặt bằng thẻ <meta>, trình duyệt bỏ qua ba directive đó (chỉ HTTP header mới có tác dụng).", consequence: "Bạn tưởng đã chống nhúng trang / bật báo cáo vi phạm, nhưng thực tế không có.", steps: [{ who: "host", text: "Chuyển CSP sang HTTP header thay vì thẻ <meta>." }], expect: "CSP được gửi qua header Content-Security-Policy." };
      case "referrer": return { saw: `Referrer-Policy đang là ${q(h("referrer-policy"))}.`, why: "Chỉ các giá trị chuẩn (no-referrer, same-origin, strict-origin-when-cross-origin…) hợp lệ. Giá trị lạ bị trình duyệt bỏ qua và dùng mặc định.", consequence: "Chính sách bạn định đặt không có hiệu lực; địa chỉ trang của khách vẫn có thể bị gửi cho website khác khi họ bấm liên kết.", steps: [{ who: "host", text: "Đặt Referrer-Policy: strict-origin-when-cross-origin." }], expect: "Header có một giá trị chuẩn.", note: (l) => /referrer-policy/i.test(l) ? "Giá trị server gửi, không thuộc danh sách chuẩn nên bị bỏ qua." : undefined };
      case "permissions": return { saw: `Permissions-Policy đang là ${q(h("permissions-policy"))}.`, why: "Cú pháp đúng là tên-tính-năng=(danh-sách), ví dụ camera=(), geolocation=(self). Sai cú pháp thì cả header bị bỏ qua.", consequence: "Các tính năng nhạy cảm (camera, vị trí, micro) thực tế không bị giới hạn như bạn tưởng.", steps: [{ who: "host", text: "Viết lại: Permissions-Policy: camera=(), microphone=(), geolocation=()." }], expect: "Header đúng cú pháp tên=(danh sách).", note: (l) => /permissions-policy/i.test(l) ? "Giá trị server gửi, sai cú pháp nên bị bỏ qua." : undefined };
      case "xss-protection": return { saw: `Header X-XSS-Protection đang bật (${q(h("x-xss-protection"))}).`, why: "Bộ lọc XSS cũ của trình duyệt đã bị gỡ vì chính nó có thể gây lỗ hổng. OWASP khuyên đặt 0 và dùng CSP.", consequence: "Không bảo vệ thêm gì ở trình duyệt hiện đại; ở trình duyệt đời cũ có thể mở thêm lỗ hổng.", steps: [{ who: "host", text: "Đặt X-Xss-Protection: 0 (hoặc bỏ hẳn) và dùng Content-Security-Policy." }], expect: "Header là 0 hoặc không còn." };
      default: return null;
    }
  },
  "tls.hsts": (f, host) => {
    const v = ev(f, "strict-transport-security");
    if (v === undefined) return { saw: `Phản hồi HTTPS của ${host} không có header Strict-Transport-Security.`, why: "HSTS dặn trình duyệt: “từ nay chỉ dùng HTTPS cho website này”. Thiếu nó, mỗi lần khách gõ hoặc bấm liên kết http:// đều có thể đi qua http:// thuần, nơi kẻ cùng mạng có thể đọc hoặc gỡ lớp mã hoá (SSL stripping). Có HSTS thì chỉ còn lần ghé đầu tiên bị hở (danh sách preload mới bịt được).", consequence: "Khách dùng wifi công cộng có thể bị ép xuống kết nối không mã hoá mà không biết, kể cả khi website có HTTPS.", steps: [{ who: "host", text: "Thêm header: Strict-Transport-Security: max-age=63072000; includeSubDomains." }, { who: "owner", text: "Chỉ thêm includeSubDomains khi mọi tên miền con đều chạy HTTPS." }], expect: "Phản hồi HTTPS có header Strict-Transport-Security với max-age lớn.", note: (l) => /strict-transport-security/i.test(l) ? "Dòng này ghi “(không có)”: server không gửi header này. Đó chính là chỗ thiếu." : undefined };
    return { saw: `HSTS có mặt nhưng chỉ kéo dài ${q(v)}.`, why: "max-age ngắn khiến trình duyệt nhanh quên quy tắc “chỉ dùng HTTPS”.", consequence: "Khách quay lại sau khoảng thời gian đó lại rơi vào lần truy cập đầu tiên không được bảo vệ.", steps: [{ who: "host", text: "Tăng max-age lên ít nhất 15552000 (6 tháng), lý tưởng là 63072000 (2 năm)." }], expect: "max-age ≥ 15552000." };
  },
  "tls.http-to-https-redirect": (f, host) => {
    const line = f.evidence.find((l) => /^GET\s+http:/i.test(l)) ?? "";
    const code = /→\s*(\d{3})/.exec(line)?.[1];
    return { saw: `Khi vào http://${host}/ máy chủ ${code ? `trả mã ${code}` : "trả nội dung"} và KHÔNG chuyển khách sang https://.`, why: "Khách gõ địa chỉ không có https hoặc bấm liên kết cũ sẽ vào bản không mã hoá; mọi thứ họ gửi và nhận đi trên đường truyền mà ai cùng mạng cũng đọc hoặc sửa được.", consequence: "Một phần khách hàng vẫn dùng bản không an toàn của website, kể cả khi bản HTTPS đã chuẩn.", steps: [{ who: "host", text: `Cấu hình máy chủ/CDN trả mã 301 (hoặc 308) từ http://${host}/ sang https://${host}/.` }, { who: "dev", text: "Với Cloudflare: SSL/TLS → Edge Certificates → bật “Always Use HTTPS”." }], expect: "Lệnh curl -sI http://… trả 301 và header Location bắt đầu bằng https://.", note: (l) => /^GET\s+http:/i.test(l) ? "Chúng tôi truy cập bản http:// và server trả lời như dòng này: không chuyển hướng sang https." : /^location/i.test(l) ? "“(không có)” nghĩa là server không chỉ khách sang địa chỉ nào khác." : undefined };
  },
  "headers.csp": (f) => {
    const v = ev(f, "content-security-policy");
    if (v === undefined) return { saw: "Phản hồi không có header Content-Security-Policy (và không có thẻ <meta> thay thế).", why: "CSP là danh sách “khách mời” cho mã chạy trên trang. Không có nó, nếu kẻ tấn công chèn được một đoạn script (XSS), trình duyệt chạy luôn mà không có lớp nào chặn.", consequence: "Một lỗi chèn mã nhỏ ở đâu đó sẽ trở thành chiếm tài khoản hoặc đánh cắp dữ liệu khách nhập.", steps: [{ who: "dev", text: "Bắt đầu bằng Content-Security-Policy-Report-Only: default-src 'self'; script-src 'self'; object-src 'none'; base-uri 'self'; frame-ancestors 'none'." }, { who: "dev", text: "Theo dõi vi phạm vài ngày rồi chuyển sang Content-Security-Policy chính thức." }], expect: "Header Content-Security-Policy có mặt và có script-src hoặc default-src hẹp.", note: (l) => /content-security-policy/i.test(l) ? "“(không có)”: server không gửi CSP." : undefined };
    return { saw: `CSP có mặt nhưng yếu: ${clip(f.summary, 200)}`, why: "CSP chỉ chống XSS khi script-src hẹp. Cho phép 'unsafe-inline' hoặc nguồn rộng (*) thì mã chèn vào vẫn được chạy.", consequence: "Bạn tưởng đã có lớp chặn mã lạ, nhưng với cấu hình này kẻ chèn được mã vẫn chạy được nó.", steps: [{ who: "dev", text: "Bỏ 'unsafe-inline' và 'unsafe-eval'; dùng nonce hoặc hash cho script nội tuyến cần thiết." }, { who: "dev", text: "Thay ký tự * bằng đúng các nguồn bạn dùng." }], expect: "script-src không còn 'unsafe-inline' hay *.", note: (l) => /content-security-policy/i.test(l) ? "Chính sách đang gửi. Hãy tìm 'unsafe-inline', ký tự * hoặc thiếu object-src/base-uri trong dòng này." : undefined };
  },
  "headers.frame-protection": (f) => ({ saw: "Phản hồi không có X-Frame-Options và CSP không có frame-ancestors.", why: "Hai header này cho trình duyệt biết ai được nhúng trang vào khung (iframe). Không có, bất kỳ website nào cũng nhúng được.", consequence: "Kẻ tấn công dựng trang giả chứa trang của bạn trong khung vô hình để dụ khách bấm nút ẩn (clickjacking).", steps: [{ who: "host", text: "Thêm X-Frame-Options: DENY, hoặc CSP: frame-ancestors 'none' (ưu tiên CSP)." }], expect: "Có X-Frame-Options hoặc frame-ancestors.", note: (l) => /x-frame-options/i.test(l) ? "“(không có)”: server không gửi header này." : /content-security-policy/i.test(l) ? "CSP hiện có (nếu có) không chứa frame-ancestors." : undefined }),
  "headers.x-content-type-options": () => ({ saw: "Phản hồi không có X-Content-Type-Options: nosniff.", why: "Không có nosniff, trình duyệt tự đoán loại tệp từ nội dung chứ không tin Content-Type.", consequence: "Một tệp người dùng tải lên (ảnh, văn bản) có thể bị trình duyệt hiểu thành script và chạy.", steps: [{ who: "host", text: "Thêm header X-Content-Type-Options: nosniff." }], expect: "Header X-Content-Type-Options: nosniff.", note: (l) => /x-content-type-options/i.test(l) ? "“(không có)”: server không gửi header này." : undefined }),
  "privacy.referrer-policy": () => ({ saw: "Phản hồi không có Referrer-Policy.", why: "Nếu không đặt, trình duyệt hiện đại dùng mặc định strict-origin-when-cross-origin (chỉ gửi tên miền sang website khác), nhưng trình duyệt cũ có thể gửi cả đường dẫn. Đặt rõ ràng để không phụ thuộc vào mặc định của từng trình duyệt.", consequence: "Nếu địa chỉ trang chứa mã thông báo hoặc ID nhạy cảm và khách dùng trình duyệt cũ, bên thứ ba có thể nhận được chúng.", steps: [{ who: "host", text: "Thêm Referrer-Policy: strict-origin-when-cross-origin." }], expect: "Có header Referrer-Policy với giá trị chuẩn.", note: (l) => /referrer-policy/i.test(l) ? "“(không có)”: server không gửi header này." : undefined }),
  "browser.cors": (f) => {
    const acao = ev(f, "Access-Control-Allow-Origin"), acac = ev(f, "Access-Control-Allow-Credentials");
    const origin = /Origin gửi đi:\s*(.+)/i.exec(f.evidence.join("\n"))?.[1]?.trim();
    const reflect = !!acao && acao === origin;
    return { saw: reflect ? `Chúng tôi giả làm một website lạ (${origin}); máy chủ trả lời CHẤP NHẬN đúng origin đó${acac === "true" ? " và cho phép kèm cookie" : ""}.` : `Máy chủ trả Access-Control-Allow-Origin: ${acao ?? "(không có)"}${acac ? ` và Allow-Credentials: ${acac}` : ""}.`, why: "CORS quyết định website nào được đọc phản hồi của bạn từ trình duyệt. Phản chiếu mọi origin nghĩa là website nào cũng được đọc, kể cả website của kẻ tấn công.", consequence: acac === "true" ? "Khách đang đăng nhập mở trang của kẻ tấn công thì trang đó đọc được dữ liệu tài khoản của họ từ website của bạn." : "Nội dung phản hồi đọc được từ bất kỳ website nào; nguy hiểm nếu cùng quy tắc áp cho API riêng tư.", steps: [{ who: "dev", text: "So sánh header Origin với danh sách cho phép tường minh và chỉ phản chiếu khi khớp." }, { who: "dev", text: "Không bao giờ kết hợp Allow-Credentials: true với origin phản chiếu hoặc *." }, { who: "dev", text: "Thêm Vary: Origin." }], expect: "Origin lạ không còn được phản chiếu.", note: (l) => /^Origin gửi đi/i.test(l) ? "Địa chỉ website giả mà chúng tôi dùng để thử. Nó không phải của bạn." : /Access-Control-Allow-Origin/i.test(l) ? (reflect ? "Trùng khớp với origin giả ở trên: máy chủ chấp nhận mọi origin." : "Giá trị máy chủ cho phép.") : /Allow-Credentials/i.test(l) ? "true = trình duyệt được gửi kèm cookie đăng nhập trong yêu cầu từ website khác." : undefined };
  },
  "cookies.flags": (f) => ({
    saw: clip(f.summary, 220), why: "Secure giữ cookie khỏi đường truyền không mã hoá; HttpOnly giữ cookie khỏi mã JavaScript (nếu bị XSS); SameSite hạn chế gửi cookie từ trang khác. Thiếu cờ nào thì mất lớp bảo vệ tương ứng.", consequence: "Cookie phiên là “chìa khoá” tài khoản: bị lấy thì kẻ tấn công vào được tài khoản mà không cần mật khẩu.",
    steps: [{ who: "dev", text: "Đặt thuộc tính Secure; HttpOnly; SameSite=Lax tại nơi ứng dụng gọi Set-Cookie (hoặc thư viện đăng nhập)." }], expect: "Set-Cookie của cookie phiên có đủ Secure, HttpOnly và SameSite.",
    note: (l) => /=<đã che>/.test(l) ? `Tên cookie và các cờ đang có: ${[/Secure/.test(l) ? "Secure" : "THIẾU Secure", /HttpOnly/i.test(l) ? "HttpOnly" : "THIẾU HttpOnly", /SameSite/i.test(l) ? "SameSite" : "THIẾU SameSite"].join(", ")}. Giá trị cookie được che.` : undefined,
  }),
  "exposure.security-txt": (_f, host) => ({ saw: `Địa chỉ https://${host}/.well-known/security.txt không có tệp (hoặc không hợp lệ).`, why: "security.txt là “số đường dây nóng” chuẩn để người phát hiện lỗi biết báo cho ai. Không có, họ không có kênh riêng để báo.", consequence: "Lỗ hổng được tìm thấy có thể bị công bố công khai hoặc bán, thay vì đến tay bạn trước.", steps: [{ who: "dev", text: "Tạo tệp /.well-known/security.txt gồm Contact: và Expires:." }, { who: "owner", text: "Chọn một địa chỉ email có người đọc thật." }], expect: "Truy cập địa chỉ trên trả 200 và có dòng Contact.", note: (l) => /^GET/i.test(l) ? "Chúng tôi truy cập đúng địa chỉ chuẩn của security.txt; kết quả như dòng này." : undefined }),
  "config.server-disclosure": (f) => {
    const lines = f.evidence.map((l) => l.trim()).filter((l) => /^(server|x-powered-by|x-aspnet|x-generator|x-drupal)/i.test(l));
    return { saw: lines.length ? `Phản hồi tiết lộ: ${lines.join("; ")}.` : clip(f.summary), why: "Số phiên bản cho kẻ quét tự động biết chính xác phần mềm bạn chạy để tra các lỗ hổng đã công bố của đúng phiên bản đó.", consequence: "Nếu phần mềm chưa vá, bot có thể thử ngay lỗ hổng đã biết mà không cần dò tìm.", steps: [{ who: "host", text: "Ẩn phiên bản: Nginx `server_tokens off;`, Apache `ServerTokens Prod`, Express `app.disable('x-powered-by')`." }, { who: "host", text: "Đồng thời giữ phần mềm luôn cập nhật: ẩn phiên bản không thay thế việc vá." }], expect: "Header Server/X-Powered-By không còn số phiên bản.", note: (l) => /^(server|x-powered-by)/i.test(l) ? "Giá trị server gửi cho mọi khách, kể cả kẻ quét tự động." : undefined };
  },
  "browser.mixed-content": (f) => ({ saw: clip(f.summary, 220), why: "Trang HTTPS tải tài nguyên qua http:// thì phần đó đi không mã hoá và có thể bị kẻ cùng mạng thay thế.", consequence: "Trình duyệt hiện đại chặn script/CSS tải qua http:// nên tính năng đó sẽ hỏng; ảnh/media được tự nâng cấp lên HTTPS hoặc, ở trình duyệt cũ, có thể bị kẻ cùng mạng thay thế.", steps: [{ who: "dev", text: "Đổi các địa chỉ http:// trong mã thành https:// (hoặc đường dẫn tương đối)." }], expect: "Không còn tham chiếu http:// trong trang." }),
  "browser.third-party-integrity": (f) => ({ saw: `Các tài nguyên từ CDN được nạp mà không có thuộc tính integrity: ${clip(f.evidence.slice(0, 3).join("; "), 200)}.`, why: "integrity là mã băm của tệp mong đợi; trình duyệt từ chối tệp nếu CDN trả về bản đã bị sửa.", consequence: "Nếu nhà cung cấp CDN bị xâm nhập, mã độc chạy ngay trên website và thấy mọi thứ khách nhập.", steps: [{ who: "dev", text: "Tính mã băm: curl -s URL | openssl dgst -sha384 -binary | openssl base64 -A rồi thêm integrity=\"sha384-…\" crossorigin=\"anonymous\"." }, { who: "dev", text: "Ghim chính xác phiên bản trong URL để mã băm luôn khớp." }], expect: "Mỗi thẻ script/link CDN có integrity.", note: (l) => /^https?:/i.test(l) ? "Tệp được nạp từ bên thứ ba mà không có kiểm tra toàn vẹn." : undefined }),
  "exposure.error-page-disclosure": (f) => ({ saw: clip(f.summary, 220), why: "Trang lỗi chỉ nên nói “có lỗi”. Chi tiết như đường dẫn, phiên bản hay stack trace giúp kẻ tấn công hiểu cấu trúc bên trong.", consequence: "Mỗi lần ai đó cố tình gây lỗi, họ nhận được bản đồ nội bộ của ứng dụng.", steps: [{ who: "dev", text: "Tắt chế độ debug ở production (DEBUG=False, NODE_ENV=production, APP_DEBUG=false…) và dùng trang lỗi chung." }], expect: "Trang 404/500 chỉ có thông điệp chung, không có đường dẫn hay stack trace." }),
  "config.debug-headers": (f) => {
    const lines = f.evidence.slice(0, 3).join("; ");
    return { saw: `Phản hồi công khai chứa header gỡ lỗi hoặc địa chỉ nội bộ: ${clip(lines, 200)}.`, why: "Header gỡ lỗi chỉ dành cho môi trường phát triển. Trên website thật chúng tiết lộ kiến trúc phía sau (tên máy chủ, thời gian xử lý, đường dẫn tới trang debug).", consequence: "Kẻ tấn công biết thêm cấu trúc hệ thống và đôi khi có liên kết tới trang profiler chứa cấu hình, truy vấn cơ sở dữ liệu hay biến môi trường.", steps: [{ who: "host", text: "Ẩn các header này ở máy chủ/CDN (Nginx: proxy_hide_header X-Debug-Token; Apache: Header unset X-Debug-Token)." }, { who: "dev", text: "Tắt chế độ debug/profiler ở production (ví dụ Symfony: APP_ENV=prod, APP_DEBUG=0)." }], expect: "Phản hồi không còn các header trên.", note: (l) => /^[a-z0-9-]+:/i.test(l) ? "Header này được gửi tới mọi khách. Nó chỉ nên tồn tại ở môi trường phát triển." : undefined };
  },
  "exposure.html-comments": (f) => ({ saw: `Trang có ${clip(f.summary, 160)}`, why: "Bình luận trong HTML ai cũng đọc được qua “Xem nguồn trang”. Từ khoá nhạy cảm (mật khẩu, token, TODO) cho thấy ghi chú nội bộ bị bỏ quên.", consequence: "Thông tin nội bộ hoặc cả thông tin đăng nhập bị bỏ quên có thể bị người lạ đọc.", steps: [{ who: "dev", text: "Xoá bình luận khỏi HTML production (minify HTML hoặc loại bỏ lúc build)." }], expect: "Không còn bình luận chứa từ khoá nhạy cảm." }),
  "config.dns-email-security": (f, host) => {
    const k = key(f), d = host.replace(/^www\./, "");
    const dns = (text: string, what: string, expect: string) => ({ why: what, steps: [{ who: "dns" as Role, text }], expect });
    const base = { saw: clip(f.summary, 200) };
    switch (k) {
      case "dmarc": return { ...base, saw: `Tên miền ${d} chưa có bản ghi DMARC (TXT tại _dmarc.${d}).`, ...dns(`Thêm bản ghi TXT _dmarc.${d} = "v=DMARC1; p=none; rua=mailto:dmarc@${d}" (bắt đầu ở chế độ theo dõi).`, "DMARC cho nhà cung cấp email biết phải làm gì với thư mạo danh tên miền của bạn. Không có, họ tự quyết, nhiều nơi vẫn cho thư giả vào hộp thư.", `dig +short TXT _dmarc.${d} trả về bản ghi bắt đầu bằng v=DMARC1.`), consequence: "Ai cũng có thể gửi email giả danh tên miền của bạn tới khách hàng và đối tác." };
      case "dmarc-policy": return { ...base, saw: "DMARC đang ở p=none: chỉ ghi nhận, không chặn thư giả.", ...dns("Theo dõi báo cáo vài tuần rồi nâng p=none lên p=quarantine, sau đó p=reject.", "p=none là điểm xuất phát hợp lý nhưng chưa bảo vệ gì; chỉ quarantine/reject mới khiến thư giả bị giữ hoặc từ chối.", "DMARC có p=quarantine hoặc p=reject."), consequence: "Thư giả mạo tên miền vẫn tới hộp thư người nhận." };
      case "spf": return { ...base, saw: `Tên miền ${d} chưa có bản ghi SPF (TXT bắt đầu bằng v=spf1).`, ...dns(`Thêm TXT ${d} = "v=spf1 include:nha-cung-cap-email ~all" (hoặc "v=spf1 -all" nếu tên miền không gửi email).`, "SPF liệt kê máy chủ nào được phép gửi email cho tên miền. Thiếu nó, thư giả dễ được chấp nhận hơn.", `dig +short TXT ${d} có một dòng v=spf1.`), consequence: "Thư mạo danh dễ lọt vào hộp thư người nhận." };
      case "caa": return { ...base, saw: `Tên miền ${d} chưa có bản ghi CAA.`, ...dns(`Thêm CAA ${d} = 0 issue "letsencrypt.org" (đổi theo nhà cấp chứng chỉ bạn dùng).`, "CAA giới hạn nhà cấp chứng chỉ nào được cấp chứng chỉ cho tên miền; thiếu nó thì bất kỳ CA nào cũng có thể cấp.", `dig +short CAA ${d} trả về dòng issue.`), consequence: "Chứng chỉ cấp nhầm hoặc lừa đảo khó bị ngăn từ gốc." };
      case "dnssec": return { ...base, saw: `Bộ phân giải không xác thực được chữ ký DNSSEC của ${d}.`, ...dns("Bật DNSSEC tại nhà cung cấp DNS rồi thêm bản ghi DS tại nhà đăng ký tên miền.", "DNSSEC ký kết quả DNS để chống giả mạo (DNS spoofing).", `dig +dnssec ${d} có cờ ad.`), consequence: "Kết quả DNS có thể bị giả mạo để dẫn khách tới máy chủ giả." };
      case "mta-sts": return { ...base, saw: `${d} nhận email (có MX) nhưng chưa có chính sách MTA-STS.`, ...dns(`Thêm TXT _mta-sts.${d} và đăng tệp chính sách tại https://mta-sts.${d}/.well-known/mta-sts.txt.`, "MTA-STS buộc máy chủ gửi thư tới bạn phải dùng TLS, không bị hạ cấp xuống dạng không mã hoá.", `dig +short TXT _mta-sts.${d} có v=STSv1.`), consequence: "Email gửi tới bạn có thể bị hạ cấp và đọc trên đường truyền." };
      default: return null;
    }
  },
};

/** Lời đọc chung cho một dòng bằng chứng khi luật không có lời riêng. */
function genericNote(line: string): string {
  const l = line.trim();
  let m = /^([a-z0-9-]+):\s*\(không có\)$/i.exec(l);
  if (m) return `Server không gửi header «${m[1]}». Đây chính là chỗ thiếu.`;
  m = /^([a-z0-9-]+):\s*(.+)$/i.exec(l);
  if (m && /^[a-z0-9-]+$/i.test(m[1]!) && m[1]!.length < 40) return `Giá trị mà server thực sự gửi cho header «${m[1]}».`;
  if (/^GET\s+\S+\s*→\s*\d{3}/i.test(l)) return "Chúng tôi truy cập địa chỉ này và máy chủ trả mã như ghi.";
  if (/^Origin gửi đi/i.test(l)) return "Địa chỉ website giả chúng tôi dùng để thử.";
  return "Giá trị quan sát được trực tiếp từ phản hồi.";
}

const ROLE_BY_CATEGORY: Record<string, Role> = { "Transport Security": "host", Headers: "host", "Browser Security": "dev", "Cookies & Sessions": "dev", Exposure: "dev", Configuration: "host", Privacy: "host" };

export function explain(f: Finding, host: string): Explanation {
  const t2 = T2[f.ruleId]?.(f, host) ?? null;
  const t = (t2 as ReturnType<Tpl> | null) ?? T[f.ruleId]?.(f, host) ?? null;
  const specific = !!t;
  const notesFor = (l: string) => t?.note?.(l) ?? genericNote(l);
  const impact = IMPACT[f.ruleId];
  const role = ROLE_BY_CATEGORY[f.category] ?? "dev";
  const steps: Step[] = t?.steps ?? (f.remediation?.steps?.length ? f.remediation.steps.slice(0, 4).map((s) => ({ who: role, text: s })) : f.remediation?.summary ? [{ who: role, text: f.remediation.summary }] : [{ who: role, text: "Gỡ hoặc ẩn thông tin này khỏi phản hồi công khai, rồi chạy lại lệnh tái hiện để xác nhận." }]);
  const repro = reproFor(f.ruleId, host);
  return {
    saw: t?.saw ?? clip(f.summary, 260),
    why: t?.why ?? f.explanation,
    consequence: t?.consequence ?? impact?.today ?? "",
    steps,
    expect: t?.expect ?? (repro ? "Chạy lại lệnh tái hiện: mục này không còn xuất hiện, hoặc quét lại để xác nhận." : "Quét lại để xác nhận mục này đã hết."),
    notes: f.evidence.map((line) => ({ line, note: notesFor(line) })),
    specific,
    certainty: t2?.certainty ?? (f.status === "unknown" ? "inconclusive" : f.status === "info" || f.confidence === "low" ? "potential" : "confirmed"),
    caveat: t2?.caveat ?? (f.status === "unknown" ? "Chưa đủ dữ liệu để kết luận; đừng hiểu là an toàn hay có lỗi." : "Đây là bằng chứng về cấu hình quan sát được; chúng tôi không thử khai thác nên chưa thể nói có bị lợi dụng hay không."),
    verify: (t2?.verify ?? (repro ? "Chạy lại lệnh tái hiện ở mục “Tái hiện”." : "")).replace(/\bHOST\b/g, host),
  };
}
