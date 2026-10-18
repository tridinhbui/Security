import type { Finding } from "./types";
import { dnsApex } from "./platform-domain";
import type { Role, Step } from "./explain";

/**
 * Mẫu giải thích theo BIẾN THỂ lỗi cho các luật trước đây chỉ có câu dựng sẵn.
 * Quy ước viết (kiểm bằng explain-quality.test.ts):
 *  - `saw` nêu giá trị/địa chỉ thật của website, không nêu lại tên luật;
 *  - `caveat` bắt buộc nói rõ giới hạn của bằng chứng khi đó mới chỉ là cấu hình/dấu hiệu — KHÔNG khẳng định khai thác được;
 *  - `certainty`: confirmed = đã quan sát trực tiếp đúng điều được nêu; potential = rủi ro tuỳ ngữ cảnh/ suy ra từ dấu hiệu;
 *    inconclusive = thiếu dữ liệu để kết luận;
 *  - `verify`: lệnh CHỈ ĐỌC để kiểm tra lại sau khi sửa.
 */
export type Certainty = "confirmed" | "potential" | "inconclusive";
export interface TplOut {
  saw?: string; why?: string; consequence?: string; steps?: Step[]; expect?: string;
  caveat?: string; certainty?: Certainty; verify?: string;
  note?: (line: string) => string | undefined;
}
export type Tpl2 = (f: Finding, host: string) => TplOut | null;

const q = (s: string) => `“${s}”`;
const clip = (s: string, n = 160) => (s.length > n ? `${s.slice(0, n - 1)}…` : s);
const S = (who: Role, text: string): Step => ({ who, text });
const key = (f: Finding) => f.fingerprint.split("|")[1] ?? "";
function ev(f: Finding, name: string): string | undefined {
  const re = new RegExp(`^${name}\\s*:\\s*(.*)$`, "i");
  for (const l of f.evidence) { const m = re.exec(l.trim()); if (m) return /^\(không có\)$/i.test(m[1]!) ? undefined : m[1]!.trim(); }
  return undefined;
}
const CFG = "Đây là bằng chứng về cấu hình mà server gửi ra. Chúng tôi không thử khai thác, nên chưa thể nói có ai đã hoặc sẽ lợi dụng được.";

export const T2: Record<string, Tpl2> = {
  /* ───────── CSP ───────── */
  "headers.csp": (f) => {
    const enforced = ev(f, "content-security-policy");
    const reportOnly = ev(f, "content-security-policy-report-only");
    const s = f.summary;
    if (enforced === undefined) {
      if (reportOnly !== undefined) return {
        saw: `Website chỉ có Content-Security-Policy-Report-Only (${q(clip(reportOnly, 120))}), chưa có CSP chính thức.`,
        why: "Chế độ Report-Only chỉ ghi nhận những gì sẽ bị chặn, trình duyệt vẫn chạy mọi thứ. Đây là bước thử nghiệm hợp lý nhưng chưa bảo vệ gì.",
        consequence: "Nếu có đoạn mã lạ chèn được vào trang, trình duyệt vẫn chạy nó như khi không có CSP.",
        caveat: "Report-Only thường là giai đoạn chuẩn bị. Nếu nhóm đang theo dõi báo cáo, đây không phải sơ suất mà là một bước chưa hoàn tất.",
        certainty: "confirmed",
        steps: [S("dev", "Xem báo cáo vi phạm đã thu được, bỏ các nguồn thật sự cần ra khỏi danh sách vi phạm."), S("dev", "Khi báo cáo yên ắng, đổi tên header thành Content-Security-Policy (giữ nguyên giá trị).")],
        expect: "Phản hồi có header Content-Security-Policy (không còn “-Report-Only”).", verify: "curl -sI https://HOST/ | grep -i content-security-policy",
      };
      return {
        saw: "Phản hồi không có header Content-Security-Policy và trang cũng không có thẻ <meta> thay thế.",
        why: "CSP là danh sách nguồn mà trình duyệt được phép chạy mã. Không có nó, một đoạn script bị chèn vào trang (XSS) sẽ được chạy bình thường.",
        consequence: "CSP không phải nguyên nhân của lỗi chèn mã, nhưng thiếu nó thì mất lớp chặn thứ hai khi có lỗi chèn mã ở đâu đó.",
        caveat: "Thiếu CSP không có nghĩa là website đang bị chèn mã. Chúng tôi chỉ xác nhận lớp phòng thủ này chưa được bật.",
        certainty: "confirmed",
        steps: [S("dev", "Bắt đầu với Content-Security-Policy-Report-Only: default-src 'self'; object-src 'none'; base-uri 'self'; frame-ancestors 'none'."), S("dev", "Theo dõi vi phạm vài ngày, thêm đúng các nguồn bạn dùng rồi chuyển sang header chính thức.")],
        expect: "Có header Content-Security-Policy với script-src hoặc default-src giới hạn.", verify: "curl -sI https://HOST/ | grep -i content-security-policy",
      };
    }
    const bits: string[] = [];
    const out: Required<Pick<TplOut, "why" | "consequence">> = { why: "", consequence: "" };
    const steps: Step[] = [];
    if (/unsafe-inline/.test(s)) { bits.push("script-src cho phép 'unsafe-inline'"); out.why += "'unsafe-inline' cho phép mọi script nằm ngay trong HTML chạy, kể cả script do kẻ tấn công chèn vào, nên CSP gần như không còn chặn XSS. "; steps.push(S("dev", "Chuyển script nội tuyến sang tệp .js riêng, hoặc gắn nonce/hash cho từng script cần thiết rồi bỏ 'unsafe-inline'.")); }
    if (/unsafe-eval/.test(s)) { bits.push("script-src cho phép 'unsafe-eval'"); out.why += "'unsafe-eval' cho phép chuỗi ký tự được chạy như mã (eval, new Function). "; steps.push(S("dev", "Tìm thư viện đang dùng eval/new Function, thay hoặc nâng cấp rồi bỏ 'unsafe-eval'.")); }
    if (/mọi host/.test(s)) { bits.push("script-src nhận script từ mọi host (* hoặc chỉ ghi https:)"); out.why += "Cho phép mọi host nghĩa là script từ bất kỳ website nào cũng được chạy, danh sách không còn giới hạn gì. "; steps.push(S("dev", "Thay * hoặc https: bằng đúng các tên miền bạn dùng (ví dụ https://cdn.example.com).")); }
    if (/data:\/blob:/.test(s)) { bits.push("script-src cho phép data:/blob:"); out.why += "data: và blob: cho phép script được dựng ngay trong trình duyệt, kẻ tấn công thường dùng để qua mặt CSP. "; steps.push(S("dev", "Bỏ data: và blob: khỏi script-src.")); }
    if (/host công cộng/.test(s)) { bits.push("script-src tin cậy host công cộng dùng chung"); out.why += "Các host công cộng (CDN, kho thư viện) chứa nhiều script của người khác; trong một số tình huống có thể mượn script ở đó để vượt CSP. "; steps.push(S("dev", "Ghim đường dẫn đầy đủ hoặc dùng hash/nonce thay vì tin cả tên miền công cộng.")); }
    if (/Không có script-src hoặc default-src/.test(s)) { bits.push("không có script-src hay default-src"); out.why += "Không có chỉ thị nào giới hạn script, nên phần còn lại của CSP không chặn được mã chèn. "; steps.push(S("dev", "Thêm script-src 'self' (hoặc default-src 'self') rồi liệt kê các nguồn thật sự cần.")); }
    if (!bits.length) bits.push(clip(s, 160));
    if (!steps.length) steps.push(S("dev", "Siết script-src theo hướng dẫn trong mục điều chỉnh."));
    out.consequence = "Bạn đã có CSP nên dễ nghĩ rằng XSS bị chặn; với cấu hình này, nếu kẻ tấn công chèn được mã vào trang thì CSP không ngăn được.";
    return {
      saw: `CSP đang bật nhưng yếu: ${bits.join("; ")}.`, why: out.why.trim(), consequence: out.consequence, steps,
      caveat: "Điểm yếu nằm ở cấu hình. Chúng tôi không tìm lỗi chèn mã trên website, nên chưa kết luận XSS có xảy ra được hay không.",
      certainty: "confirmed", expect: "script-src không còn 'unsafe-inline', 'unsafe-eval', *, data:, blob: hay host công cộng rộng.", verify: "curl -sI https://HOST/ | grep -i content-security-policy",
      note: (l) => /content-security-policy/i.test(l) ? "Chính sách đang gửi. Đọc từng chỉ thị bắt đầu bằng script-src; các từ khoá bị nêu ở trên chính là chỗ yếu." : undefined,
    };
  },

  "tls.http-to-https-redirect": (f) => key(f) !== "preloaded-tld" ? null : {
    saw: clip(f.summary, 260),
    why: "Danh sách HSTS cài sẵn là danh sách tên miền mà trình duyệt luôn tự đổi http:// thành https:// trước khi gửi bất cứ thứ gì. Cả đuôi tên miền này nằm trong danh sách đó.",
    consequence: "Khách dùng trình duyệt không thể vào bản không mã hoá. Mục này không trừ điểm.",
    steps: [S("host", "Không bắt buộc: có thể bật chuyển hướng 301 từ http:// sang https:// cho gọn (vd. Cloudflare: “Always Use HTTPS”).")],
    expect: "Không cần sửa. Nếu bật chuyển hướng: curl -sI http://… trả 301 và Location bắt đầu bằng https://.",
    certainty: "confirmed", caveat: "Danh sách đuôi được preload là danh sách bảo thủ do VibeSec duy trì; công cụ không phải trình duyệt vẫn vào được bản HTTP.",
    verify: "curl -sI http://HOST/ | grep -iE '^(HTTP|location)'",
  },
  "tls.hsts": (f) => key(f) !== "preloaded-tld" ? null : {
    saw: clip(f.summary, 260),
    why: "HSTS dặn trình duyệt chỉ dùng HTTPS. Với đuôi tên miền đã được preload toàn bộ, trình duyệt đã làm điều đó sẵn, nên thiếu header không tạo ra lỗ hổng cho khách dùng trình duyệt.",
    consequence: "Không có rủi ro thực tế với trình duyệt. Mục này không trừ điểm.",
    steps: [S("host", "Không bắt buộc: thêm Strict-Transport-Security: max-age=63072000 cho đầy đủ.")],
    expect: "Không cần sửa.", certainty: "confirmed", caveat: "Chỉ áp dụng cho trình duyệt; công cụ không phải trình duyệt không dùng danh sách preload.",
    verify: "curl -sI https://HOST/ | grep -i strict-transport",
  },

  /* ───────── CORS ───────── */
  "browser.cors": (f) => {
    const acao = ev(f, "Access-Control-Allow-Origin"), acac = ev(f, "Access-Control-Allow-Credentials")?.toLowerCase();
    const origin = /Origin gửi đi:\s*(.+)/i.exec(f.evidence.join("\n"))?.[1]?.trim();
    const creds = acac === "true";
    const caveat = "Chúng tôi chỉ thử trang chủ, không thử từng API. Chưa biết quy tắc này có áp cho endpoint chứa dữ liệu riêng tư hay không.";
    const steps: Step[] = [S("dev", "So sánh header Origin với danh sách cho phép cố định; chỉ trả Access-Control-Allow-Origin khi khớp."), S("dev", "Thêm Vary: Origin để cache không trả nhầm.")];
    const verify = "curl -sI -H 'Origin: https://khong-ton-tai.example' https://HOST/ | grep -i access-control";
    if (acao === "null") return {
      saw: `Máy chủ trả Access-Control-Allow-Origin: null${creds ? " kèm cho phép cookie" : ""}.`,
      why: "Origin “null” do trang trong iframe sandbox hoặc tệp cục bộ gửi, kẻ tấn công tạo ra nó dễ dàng. Cho phép “null” gần như là cho phép tất cả.",
      consequence: creds ? "Khách đang đăng nhập có thể bị trang lạ đọc dữ liệu tài khoản từ website này, nếu quy tắc áp cho API cần đăng nhập." : "Trang lạ có thể đọc phản hồi này từ trình duyệt của khách.",
      steps: [S("dev", "Bỏ Access-Control-Allow-Origin: null; liệt kê tường minh origin tin cậy."), ...steps.slice(1)], expect: "Origin lạ không được phản hồi cho phép.", caveat, certainty: "confirmed", verify,
    };
    if (acao === "*") return creds ? {
      saw: "Máy chủ gửi cùng lúc Access-Control-Allow-Origin: * và Allow-Credentials: true.",
      why: "Trình duyệt từ chối tổ hợp này, nên request cần cookie sẽ thất bại. Đây là dấu hiệu cấu hình nhầm, chưa phải cửa mở cho kẻ tấn công.",
      consequence: "Có thể một tính năng gọi API từ website khác đang hỏng âm thầm; rủi ro bảo mật trực tiếp thấp.",
      steps: [S("dev", "Quyết định cần credentials hay không: nếu cần, thay * bằng đúng origin tin cậy; nếu không, bỏ Allow-Credentials.")], expect: "Không còn tổ hợp * kèm credentials.", caveat: "Trình duyệt chặn tổ hợp này nên chưa phải lỗ hổng.", certainty: "confirmed", verify,
    } : {
      saw: "Máy chủ trả Access-Control-Allow-Origin: * (cho mọi website đọc, không kèm cookie).",
      why: "Dấu * nghĩa là website nào cũng đọc được phản hồi này từ trình duyệt. Với nội dung công khai (ảnh, API mở) đây là chủ ý hợp lệ.",
      consequence: "Không sao nếu phản hồi này vốn công khai; chỉ cần lưu ý nếu cùng quy tắc bị áp cho dữ liệu riêng tư.",
      steps: [S("dev", "Xác nhận trang/endpoint này thật sự công khai. Nếu có dữ liệu riêng, đổi * thành origin cụ thể.")], expect: "Chỉ nội dung công khai mới dùng *.", caveat: "Cấu hình * không kèm cookie thường là hợp lệ; chúng tôi đánh dấu để bạn xác nhận chứ chưa coi là lỗi.", certainty: "potential", verify,
    };
    const reflect = !!acao && acao === origin;
    return {
      saw: reflect ? `Chúng tôi giả làm website lạ ${origin}; máy chủ chấp nhận đúng origin đó${creds ? " và cho phép kèm cookie" : ""}.` : `Máy chủ trả Access-Control-Allow-Origin: ${acao ?? "(không có)"}.`,
      why: "CORS quyết định website nào được đọc phản hồi từ trình duyệt của khách. Máy chủ lặp lại bất kỳ origin nào nghĩa là không hề kiểm tra danh sách cho phép.",
      consequence: creds ? "Nếu endpoint cần đăng nhập cũng có quy tắc này, trang lạ mà khách đang đăng nhập ghé qua có thể đọc dữ liệu tài khoản của họ." : "Trang lạ đọc được phản hồi này; nghiêm trọng hay không tuỳ nội dung có riêng tư hay không.",
      steps, expect: "Origin lạ không còn được lặp lại trong Access-Control-Allow-Origin.", caveat, certainty: "confirmed", verify,
      note: (l) => /^Origin gửi đi/i.test(l) ? "Địa chỉ website giả (không tồn tại) mà chúng tôi dùng làm origin thử." : /allow-origin/i.test(l) ? "Giá trị máy chủ trả lại. Trùng với origin giả ở trên nghĩa là máy chủ chấp nhận mà không kiểm tra." : undefined,
    };
  },

  "exposure.security-txt": (f) => key(f) !== "unknown" ? null : {
    saw: clip(f.summary, 220),
    why: "Yêu cầu tới tệp security.txt không có câu trả lời rõ ràng (hết thời gian chờ, bị chặn hoặc lỗi máy chủ), nên không thể nói website có hay không có tệp này.",
    consequence: "Chưa có kết luận. Mục này không trừ điểm.",
    steps: [S("owner", "Quét lại sau ít phút. Nếu vẫn vậy, mở thử địa chỉ /.well-known/security.txt bằng trình duyệt.")],
    expect: "Lần quét sau trả lời rõ: có tệp (200) hoặc không có (404).", certainty: "inconclusive",
    caveat: "Không được hiểu là website thiếu security.txt.", verify: "curl -sI https://HOST/.well-known/security.txt",
  },

  /* ───────── Cookies ───────── */
  "cookies.flags": (f) => {
    const name = key(f) || "cookie";
    const line = f.evidence[0] ?? "";
    const missing = (/Thiếu:\s*([^.]*)\./.exec(f.summary)?.[1] ?? "").split(/,\s*/).filter(Boolean);
    const session = /cookie phiên/.test(f.summary);
    const steps: Step[] = [];
    const why: string[] = [];
    if (missing.includes("Secure")) { why.push("Thiếu Secure: trình duyệt có thể gửi cookie này qua http:// thuần, nơi người cùng mạng đọc được."); steps.push(S("dev", `Thêm Secure vào Set-Cookie của “${name}”.`)); }
    if (missing.includes("HttpOnly")) { why.push("Thiếu HttpOnly: mã JavaScript trên trang đọc được cookie, nên nếu có lỗi chèn mã thì cookie bị lấy."); steps.push(S("dev", `Thêm HttpOnly cho “${name}” nếu JavaScript phía giao diện không cần đọc nó.`)); }
    if (missing.includes("SameSite")) { why.push("Thiếu SameSite: trình duyệt tự chọn mặc định; trình duyệt cũ có thể gửi cookie trong request xuất phát từ trang khác (CSRF)."); steps.push(S("dev", `Đặt SameSite=Lax cho “${name}” (Strict nếu không cần liên kết từ ngoài vào).`)); }
    if (/SameSite=None bắt buộc/.test(f.summary)) { why.push("SameSite=None mà không có Secure sẽ bị trình duyệt hiện đại từ chối, cookie có thể không bao giờ được lưu."); steps.push(S("dev", "Thêm Secure, hoặc đổi SameSite=None thành Lax nếu không cần dùng xuyên website.")); }
    if (/tiền tố __/.test(f.summary)) { why.push("Tên cookie có tiền tố __Host-/__Secure- hứa hẹn bảo vệ nhưng thuộc tính chưa đáp ứng, nên trình duyệt từ chối nó."); steps.push(S("dev", "Cho cookie đủ Secure, Path=/ và không có Domain, hoặc đổi tên bỏ tiền tố.")); }
    if (/thời hạn \d+ ngày/.test(f.summary)) { why.push("Cookie phiên sống quá lâu thì cookie bị lấy vẫn dùng được trong nhiều tuần."); steps.push(S("dev", "Rút ngắn thời hạn hoặc dùng cookie phiên (không đặt Expires/Max-Age) rồi làm mới phiên khi người dùng quay lại.")); }
    if (!why.length) { why.push("Cờ bảo mật của cookie chưa đầy đủ."); steps.push(S("dev", "Đặt Secure; HttpOnly; SameSite=Lax tại nơi gọi Set-Cookie.")); }
    return {
      saw: `Cookie “${name}”${session ? " (tên giống cookie phiên đăng nhập)" : ""}: ${clip(f.summary.replace(/^Đây có vẻ là cookie phiên\/đăng nhập\.\s*/, ""), 200)}`,
      why: why.join(" "),
      consequence: session ? "Cookie phiên là chìa khoá tài khoản: bị lấy thì kẻ tấn công vào được tài khoản mà không cần mật khẩu." : "Đây có vẻ không phải cookie đăng nhập nên hậu quả nhẹ hơn; vẫn nên chỉnh để theo một chuẩn chung.",
      steps, expect: "Set-Cookie của cookie này có đủ Secure, HttpOnly và SameSite (trừ khi giao diện cần đọc nó).",
      caveat: `Việc đoán “cookie phiên” chỉ dựa vào tên cookie. ${CFG}`, certainty: session ? "confirmed" : "potential",
      verify: "curl -sI https://HOST/ | grep -i set-cookie",
      note: (l) => /=<đã che>/.test(l) ? `Tên cookie và cờ đang có: ${[/Secure/.test(l) ? "Secure" : "THIẾU Secure", /HttpOnly/i.test(l) ? "HttpOnly" : "THIẾU HttpOnly", /SameSite/i.test(l) ? "SameSite" : "THIẾU SameSite"].join(", ")}. Giá trị cookie đã được che.` : undefined,
    };
  },
  "cookies.cache-control-sensitive": (f) => ({
    saw: clip(f.summary, 220),
    why: "Trang đăng nhập/tài khoản có thể chứa thông tin cá nhân. Nếu không có Cache-Control: no-store, proxy hoặc trình duyệt dùng chung có thể lưu bản sao và phục vụ lại cho người sau.",
    consequence: "Trên máy dùng chung, nút Back có thể hiện lại trang tài khoản sau khi đã đăng xuất; với cache dùng chung, người khác có thể nhận nhầm trang.",
    caveat: "Việc coi đây là trang nhạy cảm chỉ đoán từ ô mật khẩu, URL hoặc cookie. Chúng tôi chưa chứng minh có bản sao bị lưu.", certainty: "potential",
    steps: [S("dev", "Gửi Cache-Control: no-store trên trang đăng nhập, tài khoản và mọi trang sau khi đăng nhập.")], expect: "Trang nhạy cảm có Cache-Control: no-store (hoặc private, no-cache).", verify: "curl -sI https://HOST/login | grep -i cache-control",
  }),
  "cookies.prefix": () => ({
    saw: "Cookie phiên chưa có tiền tố __Host- trong tên.",
    why: "__Host- là cách để trình duyệt tự ép cookie chỉ gắn với đúng tên miền này, qua HTTPS, nên tên miền con hoặc trang HTTP không ghi đè được.",
    consequence: "Đây là lớp tăng cường. Thiếu nó, một tên miền con bị chiếm có thể đặt cookie giả đè lên cookie phiên của bạn.",
    caveat: "Đây là gợi ý hardening, không phải lỗi. Đổi tên cookie phiên có thể làm đăng xuất mọi người một lần.", certainty: "potential",
    steps: [S("dev", "Khi có dịp bảo trì, đổi tên cookie phiên thành __Host-<tên> (cần Secure, Path=/, không Domain).")], expect: "Cookie phiên có tiền tố __Host-.", verify: "curl -sI https://HOST/ | grep -i set-cookie",
  }),

  /* ───────── TLS ───────── */
  "tls.https-available": (f, host) => {
    if (/Không hỗ trợ HTTPS/i.test(f.title) || /không chấp nhận kết nối HTTPS/.test(f.summary)) return {
      saw: `Kết nối https://${host}/ không thành công: website không chấp nhận HTTPS.`, why: "Không có HTTPS thì mọi thứ khách gửi và nhận (kể cả mật khẩu) đi nguyên văn trên đường truyền.", consequence: "Trình duyệt hiện “Không bảo mật”, nhiều khách rời đi; người cùng mạng đọc hoặc sửa được nội dung.",
      steps: [S("host", "Bật HTTPS ở hosting/CDN (Let's Encrypt hoặc chứng chỉ tự động của nền tảng)."), S("host", "Sau đó chuyển hướng toàn bộ HTTP sang HTTPS.")], expect: `https://${host}/ mở được không có cảnh báo.`, certainty: "confirmed", caveat: "Nếu lần quét gặp sự cố mạng tạm thời, hãy quét lại để chắc chắn.", verify: `curl -sI https://${host}/`,
    };
    if (f.status === "unknown") return {
      saw: "Lần quét này không kết nối ổn định qua HTTPS nên chưa kiểm tra đủ phần đường truyền.", why: "Không đủ dữ liệu để nói HTTPS tốt hay xấu.", consequence: "Chưa có kết luận. Các mục về TLS trong báo cáo này có thể thiếu.",
      steps: [S("owner", "Quét lại sau vài phút; nếu vẫn lỗi, mở https://" + host + "/ bằng trình duyệt để xem có cảnh báo không.")], expect: "Lần quét sau hoàn tất kiểm tra HTTPS.", certainty: "inconclusive", caveat: "Không được hiểu là website lỗi hay an toàn.", verify: `curl -sI https://${host}/`,
    };
    return {
      saw: `Chứng chỉ HTTPS của ${host} không được trình duyệt tin cậy: ${clip(f.summary, 160)}`, why: "Trình duyệt kiểm tra chứng chỉ có hợp lệ, khớp tên miền và có đủ chuỗi chứng chỉ trung gian. Một điều kiện sai thì hiện cảnh báo toàn màn hình.", consequence: "Khách thấy trang cảnh báo đỏ; phần lớn sẽ rời đi, số còn lại học thói quen bỏ qua cảnh báo.",
      steps: [S("host", "Cài chứng chỉ hợp lệ khớp đúng tên miền và đủ chuỗi trung gian (fullchain)."), S("host", "Nếu dùng CDN, kiểm tra chế độ SSL không phải “Off/Flexible” sai ý.")], expect: "Mở https://" + host + "/ không thấy cảnh báo.", certainty: "confirmed", caveat: "Chúng tôi dùng bộ tin cậy chuẩn; trình duyệt cũ hoặc hệ điều hành hiếm có thể khác.", verify: `curl -sI https://${host}/`,
    };
  },
  "tls.certificate-expiry": (f) => {
    const days = Number(/(\d+) ngày/.exec(f.summary)?.[1] ?? NaN);
    const soon = days <= 14;
    return {
      saw: `Chứng chỉ HTTPS còn ${Number.isNaN(days) ? "ít" : days} ngày là hết hạn.`, why: soon ? "Gần hết hạn mà chưa được gia hạn thường nghĩa là cơ chế tự gia hạn đang hỏng." : "Chứng chỉ tự gia hạn thường được làm mới khi còn khoảng 30 ngày; còn ngần này ngày chưa chắc là lỗi.",
      consequence: soon ? "Nếu hết hạn, khách thấy cảnh báo đỏ và API gọi vào bị lỗi: với khách thì website coi như sập." : "Chưa có gián đoạn. Chỉ cần theo dõi nếu số ngày không tăng lại.",
      steps: [S("host", soon ? "Gia hạn chứng chỉ ngay, sau đó kiểm tra tác vụ tự gia hạn (certbot timer, bảng điều khiển CDN)." : "Kiểm tra tự gia hạn đang chạy; quét lại sau vài ngày để xem số ngày có tăng lại không.")],
      expect: "Chứng chỉ mới có hạn ngắn (Let’s Encrypt khoảng 90 ngày; chứng chỉ công khai cấp từ 15/03/2026 tối đa 200 ngày theo CA/Browser Forum).", certainty: "confirmed", caveat: soon ? "Ngày hết hạn đọc trực tiếp từ chứng chỉ nên chắc chắn; chưa biết có tác vụ gia hạn đã lên lịch hay không." : "Có thể đây là chu kỳ bình thường của chứng chỉ ngắn hạn (ví dụ 30 ngày).", verify: "echo | openssl s_client -connect HOST:443 -servername HOST 2>/dev/null | openssl x509 -noout -enddate",
    };
  },
  "tls.certificate-strength": (f) => {
    const k = key(f);
    if (k === "weak-key") return { saw: clip(f.summary, 200), why: "Khoá càng ngắn càng dễ bị phá bằng sức tính toán. RSA dưới 2048 bit không còn được trình duyệt khuyến nghị.", consequence: "Về lý thuyết kẻ có tài nguyên lớn có thể giả mạo hoặc giải mã; trong thực tế rủi ro thấp nhưng chứng chỉ có thể bị trình duyệt từ chối.", steps: [S("host", "Tạo khoá mới (RSA 2048+ hoặc ECDSA P-256) và xin cấp lại chứng chỉ.")], expect: "Chứng chỉ mới có khoá RSA ≥ 2048 bit hoặc EC ≥ 256 bit.", certainty: "confirmed", caveat: "Chỉ đo độ dài khoá, không chứng minh khoá đã bị phá.", verify: "echo | openssl s_client -connect HOST:443 2>/dev/null | openssl x509 -noout -text | grep 'Public-Key'" };
    if (k === "long-validity") return { saw: clip(f.summary, 200), why: "Chứng chỉ công khai bị giới hạn thời hạn: tối đa 398 ngày trước 15/3/2026, 200 ngày với chứng chỉ cấp từ 15/3/2026, rồi 100 ngày (3/2027) và 47 ngày (3/2029). Hạn dài hơn 398 ngày thường là chứng chỉ do CA nội bộ/riêng cấp (không bị ràng buộc bởi quy định này) hoặc đo sai hạn.", consequence: "Chứng chỉ có thể bị trình duyệt từ chối; hạn dài cũng giữ khoá lộ hiệu lực lâu hơn.", steps: [S("host", "Dùng chứng chỉ hạn ngắn với tự động gia hạn (Let's Encrypt: 90 ngày).")], expect: "Chứng chỉ công khai mới có hạn ≤ 200 ngày (thực tế Let's Encrypt: 90 ngày).", certainty: "potential", caveat: "Nếu trình duyệt vẫn mở được site không cảnh báo, thì lỗi đo hạn có thể do chứng chỉ trung gian.", verify: "echo | openssl s_client -connect HOST:443 2>/dev/null | openssl x509 -noout -dates" };
    return { saw: clip(f.summary, 200), why: "Chứng chỉ wildcard (*.tên-miền) dùng chung một khoá cho mọi tên miền con.", consequence: "Không phải lỗi. Nếu một tên miền con bị chiếm và khoá lộ ra, kẻ tấn công giả mạo được các tên miền con khác.", steps: [S("host", "Giữ khoá riêng ở ít nơi nhất có thể; cân nhắc chứng chỉ riêng cho dịch vụ nhạy cảm.")], expect: "Biết rõ nơi nào đang giữ khoá wildcard.", certainty: "potential", caveat: "Thông tin để bạn biết, không phải phát hiện lỗi.", verify: "echo | openssl s_client -connect HOST:443 2>/dev/null | openssl x509 -noout -ext subjectAltName" };
  },
  "tls.protocol-version": (f) => ({
    saw: clip(f.summary, 200), why: "TLS 1.0 và 1.1 đã bị khai tử (RFC 8996) vì có điểm yếu thiết kế. Máy chủ còn chấp nhận nghĩa là phiên bản cũ vẫn được dùng nếu client chọn.",
    consequence: "Khách dùng trình duyệt hiện đại không bị ảnh hưởng, nhưng kẻ chen giữa có thể cố ép kết nối hạ xuống bản yếu; nhiều chuẩn tuân thủ (PCI DSS) cấm.",
    steps: [S("host", "Chỉ cho phép TLS 1.2 và 1.3 (Nginx: ssl_protocols TLSv1.2 TLSv1.3; Cloudflare: Minimum TLS Version = 1.2).")], expect: "Thử kết nối bằng TLS 1.0/1.1 bị từ chối.", certainty: "confirmed",
    caveat: "Đã xác nhận máy chủ chấp nhận bản cũ; chưa xác nhận có ai thực sự ép hạ cấp được.", verify: "echo | openssl s_client -connect HOST:443 -servername HOST -tls1 2>&1 | grep -E \"no protocols available|Cipher( is|  *:) *[A-Z]\"  # có tên cipher = server vẫn chấp nhận; “no protocols available” = máy bạn không hỗ trợ, chưa kết luận được (dùng nmap --script ssl-enum-ciphers -p 443 HOST)",
  }),
  "tls.http2": () => ({
    saw: "Máy chủ chỉ trả lời bằng HTTP/1.1, chưa thương lượng được HTTP/2.", why: "HTTP/2 tải nhiều tệp song song trên một kết nối nên nhanh hơn.", consequence: "Không phải lỗi bảo mật; chỉ ảnh hưởng tốc độ tải trang.",
    steps: [S("host", "Bật HTTP/2 ở CDN hoặc máy chủ (thường chỉ là một công tắc).")], expect: "curl --http2 báo HTTP/2.", certainty: "confirmed", caveat: "Đây là mục hiệu năng, không tính vào độ an toàn.", verify: "curl -sI --http2 https://HOST/ | head -1",
  }),
  "tls.hsts-preload": (f) => {
    const invalid = key(f) === "invalid";
    return {
      saw: invalid ? `HSTS có cờ preload nhưng chưa đủ điều kiện: ${clip(f.summary, 160)}` : "HSTS chưa sẵn sàng để vào danh sách HSTS preload của trình duyệt.",
      why: invalid ? "Cờ preload khai báo nhưng thiếu max-age ≥ 1 năm hoặc includeSubDomains, nên danh sách preload sẽ từ chối website." : "Danh sách preload được cài sẵn trong trình duyệt, bảo vệ cả lần truy cập đầu tiên mà HSTS thường không bảo vệ được.",
      consequence: "Lần truy cập đầu tiên của khách mới vẫn có thể đi qua HTTP. Đây là bước tăng cường cuối cùng, không khẩn.",
      steps: [S("host", "Đặt Strict-Transport-Security: max-age=63072000; includeSubDomains; preload."), S("owner", "Chắc chắn mọi tên miền con đều chạy HTTPS rồi mới gửi đăng ký tại hstspreload.org (khó gỡ khỏi danh sách).")], expect: "hstspreload.org báo tên miền đủ điều kiện.", certainty: "confirmed",
      caveat: "Preload là cam kết lâu dài. Không nên làm nếu còn tên miền con chạy HTTP.", verify: "curl -sI https://HOST/ | grep -i strict-transport",
    };
  },
  "tls.cipher-suite": (f) => {
    const weak = key(f) === "weak";
    return {
      saw: clip(f.summary, 200), why: weak ? "Bộ mã hoá được thương lượng nằm trong nhóm yếu (RC4, 3DES, NULL…), có thể bị phá bằng tấn công đã biết." : "Máy chủ cho phép bộ mã hoá TLS 1.2 chưa tối ưu, ví dụ thiếu forward secrecy.",
      consequence: weak ? "Kết nối vẫn có mã hoá nhưng yếu hơn tiêu chuẩn; lưu lượng đã ghi lại có thể bị giải mã." : "Kết nối vẫn mã hoá. Thiếu forward secrecy nghĩa là nếu khoá riêng lộ sau này, lưu lượng ghi trước đó đọc được.",
      steps: [S("host", "Dùng cấu hình TLS khuyến nghị (Mozilla SSL Configuration Generator, mức Intermediate).")], expect: "Bộ mã hoá thương lượng là AEAD (AES-GCM/ChaCha20) với ECDHE.", certainty: weak ? "confirmed" : "potential",
      caveat: "Chúng tôi chỉ kiểm tra bộ mã hoá được thương lượng khi quét; client khác có thể thương lượng khác.", verify: "openssl s_client -connect HOST:443 </dev/null 2>/dev/null | grep -i cipher",
    };
  },
  "tls.www-consistency": (f) => {
    const noResp = f.status === "info";
    return {
      saw: clip(f.summary, 200), why: noResp ? "Phiên bản còn lại của tên miền (có hoặc không www) tồn tại trong DNS nhưng không trả lời HTTPS." : "Phiên bản còn lại của tên miền (có hoặc không www) có chứng chỉ lỗi hoặc không khớp.",
      consequence: "Khách gõ địa chỉ theo kiểu kia sẽ thấy lỗi hoặc cảnh báo, dù website chính hoạt động tốt.", steps: [S("host", "Thêm cả hai tên miền vào chứng chỉ và chuyển hướng 301 một bản sang bản chính.")], expect: "Cả hai địa chỉ đều mở được hoặc chuyển hướng về bản chính.", certainty: noResp ? "potential" : "confirmed",
      caveat: noResp ? "Nếu bạn chủ ý không dùng địa chỉ này thì có thể bỏ qua." : "Chỉ kiểm tra chứng chỉ của bản còn lại.", verify: "curl -sI https://www.HOST/ ; curl -sI https://HOST/",
    };
  },
  "tls.insecure-login-form": (f) => {
    const k = key(f);
    if (k === "method-get" && /không ghi method/.test(f.summary)) return { saw: "Một form có ô mật khẩu không ghi thuộc tính method. Nếu được gửi trực tiếp (không qua JavaScript), trình duyệt dùng GET và đặt mật khẩu lên URL.", why: "URL có mật khẩu sẽ nằm trong lịch sử trình duyệt, nhật ký máy chủ và header Referer.", consequence: "Nếu form thật sự gửi bằng GET, mật khẩu có thể nằm lại ở nhiều nơi. Nếu form do JavaScript gửi bằng POST (thường gặp ở React/Next.js) thì không có rủi ro này.", steps: [S("dev", "Thêm method=\"post\" vào thẻ <form> đăng nhập, kể cả khi đã xử lý bằng JavaScript (phòng khi JavaScript chưa tải xong mà người dùng đã bấm Enter).")], expect: "Thẻ <form> đăng nhập có method=\"post\".", certainty: "potential", caveat: "VibeSec không chạy JavaScript nên không biết form có được JavaScript gửi bằng POST hay không.", verify: "curl -s https://HOST/ | grep -io '<form[^>]*>'" };
    if (k === "method-get") return { saw: "Một form có ô mật khẩu gửi dữ liệu bằng GET.", why: "GET đặt dữ liệu form vào địa chỉ URL, nên mật khẩu xuất hiện trong lịch sử trình duyệt, nhật ký máy chủ và header Referer.", consequence: "Mật khẩu có thể nằm lại trong nhật ký và lịch sử mà nhiều người đọc được.", steps: [S("dev", "Đổi form sang method=\"post\".")], expect: "Form đăng nhập dùng method=\"post\".", certainty: "confirmed", caveat: "Đã thấy trong HTML của trang; chưa xác nhận máy chủ có thật sự ghi mật khẩu vào nhật ký.", verify: "curl -s https://HOST/ | grep -i '<form'" };
    if (k === "page-http") return { saw: "Một trang có ô mật khẩu được phục vụ qua http:// không mã hoá.", why: "Trang HTTP có thể bị sửa trên đường đi, ví dụ thay form để gửi mật khẩu cho kẻ khác.", consequence: "Người cùng mạng có thể đọc hoặc đánh tráo trang đăng nhập.", steps: [S("host", "Phục vụ trang đăng nhập chỉ qua HTTPS và chuyển hướng HTTP sang HTTPS.")], expect: "Trang đăng nhập chỉ mở qua https://.", certainty: "confirmed", caveat: "Chỉ ảnh hưởng người dùng truy cập bằng http:// trên mạng không tin cậy.", verify: "curl -sI http://HOST/login" };
    return { saw: "Một form có ô mật khẩu gửi dữ liệu tới địa chỉ http://.", why: "Địa chỉ nhận form không có mã hoá nên mật khẩu đi nguyên văn trên đường truyền.", consequence: "Người cùng mạng đọc được mật khẩu khách vừa nhập.", steps: [S("dev", "Đổi action của form sang https:// (hoặc đường dẫn tương đối trên trang HTTPS).")], expect: "action của form bắt đầu bằng https:// hoặc /.", certainty: "confirmed", caveat: "Máy chủ có thể chuyển hướng sang HTTPS trước khi nhận, nhưng dữ liệu đã bị gửi đi rồi.", verify: "curl -s https://HOST/ | grep -i '<form'" };
  },

  /* ───────── Redirect / config ───────── */
  "config.suspicious-redirects": (f) => {
    const k = key(f).split(":")[0];
    const m: Record<string, TplOut> = {
      downgrade: { saw: clip(f.summary, 200), why: "Chuỗi chuyển hướng đi từ HTTPS xuống HTTP, bỏ lớp mã hoá giữa chừng.", consequence: "Request đó đi qua đường truyền không bảo vệ.", steps: [S("host", "Sửa quy tắc redirect trỏ tới https:// và kiểm tra X-Forwarded-Proto.")], expect: "Mọi bước chuyển hướng đều ở HTTPS.", certainty: "confirmed", caveat: "Chỉ ảnh hưởng đường dẫn này.", verify: "curl -sIL https://HOST/ | grep -i location" },
      long: { saw: clip(f.summary, 200), why: "Mỗi bước chuyển hướng thêm độ trễ và một chỗ có thể sai.", consequence: "Trang tải chậm hơn; rủi ro bảo mật gián tiếp.", steps: [S("host", "Chuyển hướng thẳng tới địa chỉ cuối cùng trong một bước.")], expect: "Tối đa 1–2 bước.", certainty: "confirmed", caveat: "Chỉ là chuỗi chuyển hướng dài, không phải lỗ hổng bảo mật.", verify: "curl -sIL https://HOST/ | grep -ci '^location'" },
      ip: { saw: clip(f.summary, 200), why: "Địa chỉ IP trần không có chứng chỉ HTTPS thông thường, và là mẫu hay thấy ở website bị chiếm hoặc cấu hình sai.", consequence: "Khách bị đưa tới địa chỉ không tên; có thể là sai cấu hình hoặc dấu hiệu bị chiếm.", steps: [S("host", "Chuyển hướng tới tên miền của bạn thay vì IP.")], expect: "Chuyển hướng dùng tên miền.", certainty: "potential", caveat: "Có thể do cấu hình tạm của nhà cung cấp. Cần người có quyền xem lại.", verify: "curl -sIL https://HOST/ | grep -i location" },
      blocked: { saw: clip(f.summary, 200), why: "VibeSec chỉ quét website công khai trên cổng chuẩn, nên không đi theo chuyển hướng này.", consequence: "Phần đằng sau chuyển hướng chưa được quét.", steps: [S("owner", "Nếu đích là hệ thống nội bộ dùng thật, không cần làm gì; nếu không, kiểm tra quy tắc chuyển hướng.")], expect: "Biết rõ chuyển hướng đi đâu.", certainty: "inconclusive", caveat: "Chúng tôi cố ý không kết nối, nên không kết luận gì về đích.", verify: "curl -sI https://HOST/" },
      "meta-refresh": { saw: clip(f.summary, 200), why: "Thẻ meta refresh sang tên miền khác là mẫu của trang tên miền đậu hoặc trang bị chiếm.", consequence: "Khách bị đưa sang website khác mà không biết.", steps: [S("dev", "Xác nhận đích do bạn chủ ý đặt; nếu không, xoá thẻ meta và tìm nguồn chèn.")], expect: "Không còn chuyển hướng ngoài ý muốn.", certainty: "potential", caveat: "Rebrand và chuyển domain hợp lệ cũng trông như vậy.", verify: "curl -s https://HOST/ | grep -i 'http-equiv=\"refresh\"'" },
      "cross-domain": { saw: clip(f.summary, 200), why: "Website chuyển hướng sang tên miền khác; thường do đổi thương hiệu.", consequence: "Thông tin, không phải lỗi.", steps: [S("owner", "Xác nhận đây là chủ ý.")], expect: "Chủ ý được xác nhận.", certainty: "potential", caveat: "Không nên coi là lỗi.", verify: "curl -sIL https://HOST/ | grep -i location" },
    };
    return m[k ?? ""] ?? null;
  },
  "config.auth-surface": (f) => ({
    saw: clip(f.summary, 220), why: "Trang chứa dấu hiệu có đăng nhập hoặc khu vực riêng; kẻ tấn công cũng thấy điều này.", consequence: "Không phải lỗ hổng. Nó cho biết kiểm soát truy cập ở đâu cần kiểm tra kỹ.",
    steps: [S("dev", "Kiểm tra giới hạn số lần đăng nhập sai, khoá tài khoản và xác thực nhiều bước ở các màn hình này.")], expect: "Các màn hình đăng nhập có giới hạn thử sai và MFA.", certainty: "potential", caveat: "VibeSec không đăng nhập và không thử mật khẩu, nên không nói gì về độ mạnh của xác thực.", verify: "curl -sI https://HOST/login",
  }),
  "config.technology": (f) => ({
    saw: clip(f.summary, 220), why: "Dấu vân tay công nghệ dựa vào dấu hiệu công khai trên trang để chọn hướng dẫn sửa đúng nền tảng.", consequence: "Không phải lỗi; chỉ ảnh hưởng độ chính xác của hướng dẫn sửa trong báo cáo.", steps: [S("owner", "Kiểm tra danh sách có đúng với thực tế không; nếu sai, hướng dẫn sửa có thể lệch.")], expect: "Danh sách khớp công nghệ bạn dùng.", certainty: "potential", caveat: "Nhận diện có thể thiếu hoặc sai.", verify: "curl -sI https://HOST/",
  }),
  "config.http-methods": (f) => {
    const trace = key(f) === "trace";
    return {
      saw: clip(f.summary, 200), why: trace ? "TRACE/TRACK trả lại nguyên request, từng bị lợi dụng để lấy cookie HttpOnly qua XST." : "Máy chủ công bố phương thức ghi (PUT, DELETE…) trên trang chủ.", consequence: trace ? "Rủi ro thực tế thấp với trình duyệt hiện đại, nhưng không có lý do nào để bật." : "Phương thức được công bố chưa chắc dùng được; cần quyền mới ghi được.",
      steps: [S("host", trace ? "Tắt TRACE/TRACK (Nginx: mặc định tắt; Apache: TraceEnable off)." : "Giới hạn phương thức ở GET/HEAD/POST cho trang chủ.")], expect: "OPTIONS không liệt kê phương thức nguy hiểm.", certainty: trace ? "confirmed" : "potential",
      caveat: trace ? "Chúng tôi chỉ đọc danh sách phương thức công bố." : "Header Allow chỉ là công bố. Chúng tôi không gửi PUT/DELETE nên không biết máy chủ có thật sự cho ghi.", verify: "curl -sI -X OPTIONS https://HOST/ | grep -i allow",
    };
  },

  /* ───────── DNS / Email ───────── */
  "config.dns-email-security": (f, host) => {
    const d = dnsApex(host);
    const k = key(f);
    const dig = `dig +short TXT ${d}`;
    const base = (t: TplOut): TplOut => ({ certainty: "confirmed", caveat: "Kết quả từ bộ phân giải DNS công khai; DNS vừa đổi có thể cần chờ vài giờ để cập nhật. Chúng tôi không biết tên miền này có thật sự gửi email hay không.", ...t });
    switch (k) {
      case "platform": {
        const suffix = /Hậu tố nền tảng[^:]*:\s*(\S+)/.exec(f.evidence.join("\n"))?.[1] ?? "nền tảng";
        return {
          saw: `Website đang chạy trên tên miền con của ${suffix} (tên miền do nền tảng sở hữu, không phải của bạn).`,
          why: `SPF, DMARC, CAA, DNSSEC là các bản ghi DNS đặt ở tên miền gốc. Tên miền gốc ${suffix} thuộc nền tảng, nên bạn không thêm hay sửa được các bản ghi này, và chúng không nói lên điều gì về cấu hình của bạn.`,
          consequence: "Không có việc gì cần làm lúc này. Mục này không trừ điểm.",
          steps: [S("owner", "Khi chuyển sang tên miền riêng (vd. tencongty.vn), quét lại: lúc đó VibeSec sẽ kiểm tra SPF/DMARC/CAA của tên miền đó và hướng dẫn cách thêm.")],
          expect: "Không cần sửa. Với tên miền riêng, quét lại để kiểm tra các bản ghi email/DNS.",
          certainty: "confirmed", caveat: "Nhận biết tên miền nền tảng dựa trên danh sách Public Suffix List; nền tảng mới chưa có trong danh sách có thể chưa được nhận ra.",
          verify: suffix === "nền tảng" ? "Quét lại sau khi chuyển sang tên miền riêng." : `dig +short NS ${suffix}   # máy chủ tên thuộc nền tảng, không phải của bạn`,
        };
      }
      case "dmarc-pct": return base({ saw: clip(f.summary, 200), why: "pct nhỏ hơn 100 nghĩa là chỉ một phần thư vi phạm bị xử lý.", consequence: "Một phần thư giả vẫn lọt vào.", steps: [S("dns", "Tăng pct lên 100 khi chắc thư hợp lệ đều qua được.")], expect: "Bản ghi DMARC không còn pct<100 hoặc pct=100.", verify: `dig +short TXT _dmarc.${d}`, certainty: "potential", caveat: "pct<100 hợp lệ khi đang triển khai dần." });
      case "spf-plus-all": return base({ saw: "SPF kết thúc bằng +all (hoặc all không dấu): mọi máy chủ trên Internet đều được coi là hợp lệ.", why: "Với +all, bước kiểm tra SPF luôn cho qua, tức là SPF vô hiệu.", consequence: "Ai cũng gửi được thư mạo tên miền mà SPF vẫn báo hợp lệ.", steps: [S("dns", "Đổi +all thành -all (hoặc ~all khi thử nghiệm) sau khi liệt kê đủ nguồn gửi hợp lệ.")], expect: "SPF kết thúc bằng -all hoặc ~all.", verify: dig });
      case "spf-neutral": return base({ saw: "SPF kết thúc bằng ?all (trung lập).", why: "?all không khẳng định thư từ nguồn lạ là hợp lệ hay giả, nên không giúp chặn.", consequence: "Thư giả không bị đánh dấu.", steps: [S("dns", "Đổi ?all thành ~all hoặc -all.")], expect: "SPF kết thúc bằng ~all hoặc -all.", verify: dig });
      case "spf-lookups": return base({ saw: clip(f.summary, 200), why: "SPF chỉ cho phép tối đa 10 truy vấn DNS. Vượt thì nhà nhận trả lỗi vĩnh viễn và có thể bỏ qua SPF.", consequence: "Thư hợp lệ có thể bị coi là lỗi SPF, hoặc SPF không còn tác dụng.", steps: [S("dns", "Gộp bớt include hoặc dùng dịch vụ SPF flattening.")], expect: "Số truy vấn ≤ 10.", verify: dig, certainty: "potential", caveat: "Số truy vấn là ước tính từ include/redirect, không phải đo thực tế ở nhà nhận." });
      case "spf-multiple": return base({ saw: clip(f.summary, 200), why: "Theo RFC 7208 chỉ được có một bản ghi SPF; nhiều hơn một thì toàn bộ kiểm tra SPF lỗi.", consequence: "SPF bị vô hiệu với nhiều nhà nhận.", steps: [S("dns", "Gộp mọi cơ chế vào một bản ghi v=spf1 duy nhất.")], expect: "Chỉ còn một bản ghi v=spf1.", verify: dig });
      case "ns-single": return base({ saw: clip(f.summary, 200), why: "Chỉ có một máy chủ tên: nếu nó sập, website và email không phân giải được.", consequence: "Một sự cố ở nhà cung cấp DNS làm cả tên miền biến mất.", steps: [S("dns", "Thêm ít nhất một máy chủ tên thứ hai, tốt nhất ở nhà cung cấp khác.")], expect: "NS có ≥ 2 máy chủ.", verify: `dig +short NS ${d}`, certainty: "potential", caveat: "Một số nhà cung cấp lớn che nhiều máy chủ sau một tên (anycast); khi đó đây là cảnh báo nhẹ." });
      default: return null;
    }
  },

  /* ───────── Headers khác ───────── */
  "headers.charset": () => ({
    saw: "Trang HTML không khai báo bảng mã ký tự (charset) trong header hay thẻ meta.", why: "Không khai báo thì trình duyệt tự đoán; đoán sai có thể hiểu nhầm nội dung chèn vào như mã chạy được.", consequence: "Rủi ro thấp, gần như chỉ có ý nghĩa khi đã có lỗi chèn nội dung ở nơi khác; hiếm hơn là chữ bị lỗi font.",
    steps: [S("dev", "Thêm <meta charset=\"utf-8\"> ở đầu <head>, hoặc Content-Type: text/html; charset=utf-8.")], expect: "Content-Type hoặc thẻ meta có charset=utf-8.", certainty: "confirmed", caveat: "Là hardening nhẹ, không chứng minh có lỗi chèn nội dung.", verify: "curl -sI https://HOST/ | grep -i content-type",
  }),
  "headers.cache-policy": (f) => {
    const cookie = key(f) === "cookie-cacheable";
    return {
      saw: clip(f.summary, 200), why: cookie ? "Trang vừa đặt cookie vừa cho cache dùng chung lưu (public/max-age lớn) có thể bị CDN lưu và phát lại cho người khác, kèm cookie." : "Trang HTML không khai báo Cache-Control nên proxy/CDN tự quyết thời gian lưu.", consequence: cookie ? "Nếu CDN lưu bản có cookie phiên, người sau có thể nhận cookie của người trước." : "Trang có thể được lưu quá lâu hoặc không được lưu đúng; thường chỉ ảnh hưởng độ mới.",
      steps: [S("host", cookie ? "Đặt Cache-Control: private, no-store cho trang đặt cookie, hoặc cấu hình CDN bỏ qua cache khi có cookie." : "Đặt Cache-Control phù hợp (ví dụ public, max-age=300 cho trang tĩnh).")], expect: cookie ? "Trang có cookie không còn public/cacheable." : "Có Cache-Control rõ ràng.", certainty: cookie ? "potential" : "confirmed",
      caveat: cookie ? "Chúng tôi thấy cấu hình cho phép, chưa chứng minh có CDN nào đang lưu thật." : "Thiếu header là thiếu khai báo, chưa phải lỗi.", verify: "curl -sI https://HOST/ | grep -i -E 'cache-control|set-cookie|age'",
    };
  },
  "headers.cross-origin-isolation": () => ({
    saw: "Trang chưa dùng các header cách ly origin (COOP/COEP/CORP).", why: "Các header này tách trang khỏi cửa sổ website khác và giảm rủi ro rò rỉ qua kênh phụ; chủ yếu cần cho trang dùng SharedArrayBuffer hoặc xử lý dữ liệu rất nhạy cảm.", consequence: "Với đa số website, không có hậu quả đáng kể.",
    steps: [S("host", "Cân nhắc Cross-Origin-Opener-Policy: same-origin nếu trang không cần popup liên website.")], expect: "Có COOP phù hợp.", certainty: "potential", caveat: "Mục hardening nâng cao; bật nhầm có thể làm hỏng đăng nhập bằng popup (Google, thanh toán).", verify: "curl -sI https://HOST/ | grep -i cross-origin",
  }),
  "headers.deprecated": (f) => ({
    saw: clip(f.summary, 200), why: "Header này đã lỗi thời; trình duyệt hiện đại bỏ qua hoặc coi là nguy cơ.", consequence: "Thường không có hậu quả; chỉ gây hiểu nhầm là đã được bảo vệ.", steps: [S("host", "Gỡ header lỗi thời và dùng CSP thay thế.")], expect: "Phản hồi không còn header đó.", certainty: "confirmed", caveat: "Mức thông tin, ảnh hưởng nhẹ; không phải lỗ hổng khai thác được.", verify: "curl -sI https://HOST/",
  }),

  /* ───────── Privacy ───────── */
  "privacy.permissions-policy": () => ({
    saw: "Phản hồi không có Permissions-Policy.", why: "Header này liệt kê tính năng trình duyệt (camera, mic, vị trí) mà trang và iframe được dùng. Không có, iframe bên thứ ba có thể xin quyền theo mặc định của trình duyệt.", consequence: "Không phải lỗi; chỉ là thiếu lớp giới hạn thêm.",
    steps: [S("host", "Thêm Permissions-Policy: camera=(), microphone=(), geolocation=() nếu trang không dùng các tính năng đó.")], expect: "Có Permissions-Policy.", certainty: "confirmed", caveat: "Mức thông tin; đặt sai có thể tắt tính năng bạn đang dùng.", verify: "curl -sI https://HOST/ | grep -i permissions-policy",
  }),
  "privacy.third-party-origins": (f) => ({
    saw: clip(f.summary, 220), why: "Mỗi bên thứ ba bạn tải tài nguyên từ đó nhận được địa chỉ IP và thông tin trình duyệt của khách.", consequence: "Ảnh hưởng quyền riêng tư và độ phụ thuộc; không phải lỗi.", steps: [S("owner", "Rà lại danh sách, bỏ bên không cần và ghi vào chính sách quyền riêng tư.")], expect: "Mỗi bên thứ ba đều có lý do.", certainty: "confirmed", caveat: "Chỉ liệt kê, không đánh giá bên đó có đáng tin hay không.", verify: "curl -s https://HOST/ | grep -o 'src=\"https://[^/]*' | sort -u",
  }),
  "privacy.trackers": (f) => ({
    saw: clip(f.summary, 220), why: "Trình theo dõi/quảng cáo thu thập hành vi khách và gửi cho bên thứ ba.", consequence: "Có thể cần banner đồng ý theo luật (GDPR, Nghị định 13/2023).", steps: [S("owner", "Xác nhận có chủ ý, có thông báo và có cơ chế đồng ý nếu luật yêu cầu.")], expect: "Chỉ trình theo dõi có chủ ý và có thông báo.", certainty: "confirmed", caveat: "Chúng tôi phát hiện theo tên miền/script quen thuộc; không biết nó chạy trước hay sau khi khách đồng ý.", verify: "curl -s https://HOST/ | grep -io 'googletagmanager\\|facebook.net\\|hotjar'",
  }),

  /* ───────── Exposure ───────── */
  "exposure.secrets": (f) => ({
    saw: clip(f.summary, 220), why: "Một chuỗi giống khoá/bí mật nằm trong tệp công khai. Ai tải tệp đó cũng đọc được.", consequence: "Nếu là khoá thật còn hiệu lực, người lạ có thể dùng dịch vụ đó thay bạn (tốn tiền, đọc dữ liệu).",
    steps: [S("dev", "Xác định chuỗi này là khoá gì. Nếu còn hiệu lực, thu hồi và tạo khoá mới NGAY (đừng chỉ xoá khỏi tệp)."), S("dev", "Chuyển bí mật sang biến môi trường phía máy chủ; chỉ khoá công khai mới được nằm trong mã giao diện.")], expect: "Khoá cũ bị thu hồi và tệp công khai không còn chuỗi đó.",
    certainty: "potential", caveat: "VibeSec khớp mẫu chuỗi và che giá trị, không thử dùng khoá. Nhiều khoá (như Stripe publishable key, Firebase API key) được thiết kế để công khai nên có thể là false positive.", verify: "curl -s URL_TEP | grep -c 'chuỗi-đã-che'",
  }),
  "exposure.public-config": (f) => {
    const sens = key(f) === "sensitive-names";
    return {
      saw: clip(f.summary, 200), why: sens ? "Cấu hình công khai chứa biến có tên như SECRET, TOKEN hay PRIVATE. Nếu giá trị là thật, ai xem nguồn trang cũng thấy." : "Trang gửi xuống trình duyệt một số giá trị môi trường (NEXT_PUBLIC_…, REACT_APP_…).", consequence: sens ? "Bí mật thật nằm ở đây có thể bị người lạ dùng." : "Thông tin chủ yếu, đa số giá trị này công khai theo thiết kế.",
      steps: [S("dev", sens ? "Kiểm tra từng biến: nếu thật là bí mật, thu hồi và chuyển sang phía máy chủ." : "Rà lại danh sách xem có giá trị nào không nên công khai.")], expect: "Không có bí mật nào trong cấu hình công khai.", certainty: sens ? "potential" : "confirmed",
      caveat: sens ? "Chỉ đoán từ tên biến; giá trị chưa được kiểm tra có phải bí mật thật hay không." : "Liệt kê để bạn biết, không phải lỗi.", verify: "curl -s https://HOST/ | grep -o 'NEXT_PUBLIC_[A-Z_]*'",
    };
  },
  "exposure.source-maps": () => ({
    saw: "Tệp source map (.map) của JavaScript tải về được công khai.", why: "Source map chứa mã nguồn gốc chưa nén, tên biến và cấu trúc thư mục.", consequence: "Người ngoài đọc mã nguồn giao diện dễ dàng, nhanh tìm lỗi và endpoint nội bộ. Bản thân việc này không phải lỗ hổng, nhưng giúp ích cho kẻ tấn công.",
    steps: [S("dev", "Tắt tạo source map cho bản production, hoặc không triển khai tệp .map lên máy chủ công khai.")], expect: "Truy cập đường dẫn .map trả 404.", certainty: "confirmed", caveat: "Mã giao diện vốn gửi về trình duyệt; source map chỉ làm dễ đọc hơn.", verify: "curl -sI https://HOST/DUONG_DAN.js.map",
  }),
  "exposure.robots-txt": (f) => ({
    saw: clip(f.summary, 200), why: f.status === "info" && /không có/i.test(f.summary) ? "robots.txt chỉ là gợi ý cho bot tìm kiếm, không phải biện pháp bảo mật." : "robots.txt công khai nên mọi người đọc được những đường dẫn nó nêu.", consequence: "Đường dẫn trông nhạy cảm (admin, backup) nêu trong robots.txt chỉ dẫn đường cho người tò mò; không phải lỗ hổng nếu chúng đã được bảo vệ.",
    steps: [S("dev", "Đừng dùng robots.txt để giấu trang nhạy cảm; hãy bảo vệ chúng bằng đăng nhập hoặc IP allowlist.")], expect: "Các đường dẫn nhạy cảm yêu cầu đăng nhập dù có hay không trong robots.txt.", certainty: "potential", caveat: "Chỉ liệt kê tên đường dẫn; chúng tôi không truy cập chúng để thử.", verify: "curl -s https://HOST/robots.txt",
  }),
  "exposure.sitemap-xml": () => ({
    saw: "Không có sitemap.xml ở vị trí mặc định.", why: "Sitemap giúp công cụ tìm kiếm lập chỉ mục, không liên quan bảo mật.", consequence: "Không có hậu quả bảo mật.", steps: [S("owner", "Chỉ cần nếu bạn muốn website xuất hiện tốt trên Google.")], expect: "Có sitemap.xml nếu cần SEO.", certainty: "confirmed", caveat: "Mức thông tin, không phải lỗi bảo mật.", verify: "curl -sI https://HOST/sitemap.xml",
  }),
  "exposure.outdated-libraries": (f) => ({
    saw: clip(f.summary, 220), why: "Thư viện JavaScript phiên bản cũ có thể chứa lỗ hổng công khai đã có số CVE.", consequence: "Tuỳ lỗ hổng: có thể dùng để chèn mã hoặc đánh cắp dữ liệu nếu trang dùng đúng chức năng bị lỗi.",
    steps: [S("dev", "Nâng cấp thư viện lên bản mới đã vá; chạy kiểm thử vì có thể có thay đổi không tương thích.")], expect: "Phiên bản thư viện nằm ngoài khoảng bị ảnh hưởng.", certainty: "potential",
    caveat: "Phiên bản được đoán từ tên tệp/chú thích, và lỗ hổng chỉ khai thác được nếu trang gọi đúng chức năng bị lỗi. Chúng tôi không thử khai thác.", verify: "curl -s https://HOST/ | grep -o 'jquery[^\"]*\\.js'",
  }),
  "exposure.subdomain-takeover": (f) => ({
    saw: clip(f.summary, 220), why: "Một tên miền con trỏ tới dịch vụ bên ngoài (GitHub Pages, Heroku…) đã bị xoá. Người lạ có thể đăng ký lại tài nguyên đó và nhận luôn tên miền con.", consequence: "Kẻ chiếm có thể dựng trang giả dưới tên miền của bạn để lừa khách.",
    steps: [S("dns", "Xoá bản ghi DNS (CNAME) nếu dịch vụ không còn dùng, hoặc tạo lại tài nguyên ở dịch vụ để giữ chỗ.")], expect: "Tên miền con không còn trỏ vào tài nguyên không tồn tại.", certainty: f.confidence === "high" ? "confirmed" : "potential",
    caveat: "Chúng tôi thấy dấu hiệu CNAME trỏ vào dịch vụ trống, chưa đăng ký thử tài nguyên đó, nên chưa chứng minh chiếm được.", verify: "dig +short CNAME TENMIEN_CON",
  }),
  "exposure.internal-references": (f) => ({
    saw: clip(f.summary, 200), why: "Trang công khai nhắc tới địa chỉ mạng nội bộ (10.x, 192.168.x, localhost…).", consequence: "Cho kẻ tấn công biết một phần cấu trúc mạng nội bộ; thường chỉ là sót mã cấu hình.", steps: [S("dev", "Gỡ tham chiếu nội bộ khỏi mã giao diện production.")], expect: "Không còn địa chỉ nội bộ trong trang.", certainty: "confirmed", caveat: "Địa chỉ nội bộ không dùng được từ Internet; chỉ là rò rỉ thông tin.", verify: "curl -s https://HOST/ | grep -E '192\\.168|10\\.[0-9]+\\.[0-9]+\\.[0-9]+|localhost'",
  }),
  "browser.form-targets": (f) => ({
    saw: clip(f.summary, 200), why: "Form có ô mật khẩu gửi dữ liệu tới tên miền khác. Thường thấy khi dùng dịch vụ đăng nhập bên ngoài, nhưng cũng là chiêu của trang lừa đảo.", consequence: "Mật khẩu đi tới bên khác; cần chắc đó là dịch vụ bạn chủ ý dùng.", steps: [S("dev", "Xác nhận tên miền đích thuộc nhà cung cấp đăng nhập tin cậy; nếu không, sửa action của form.")], expect: "Form đăng nhập gửi về đúng tên miền của bạn hoặc nhà cung cấp tin cậy.", certainty: "potential", caveat: "Dịch vụ đăng nhập bên ngoài là cấu hình hợp lệ phổ biến.", verify: "curl -s https://HOST/ | grep -i '<form'",
  }),

  /* ───────── Advanced ───────── */
  "adv.certificate-hygiene": (f) => ({ saw: clip(f.summary, 200), why: "Chứng chỉ có một số điểm chưa theo thực hành tốt (phạm vi hoặc hạn rộng hơn cần).", consequence: "Chưa gây lỗi; làm tăng thiệt hại nếu khoá riêng lộ.", steps: [S("host", "Dùng chứng chỉ hạn ngắn, phạm vi vừa đủ.")], expect: "Chứng chỉ phạm vi hẹp và hạn ngắn.", certainty: "potential", caveat: "Gợi ý vệ sinh, không phải lỗi.", verify: "echo | openssl s_client -connect HOST:443 2>/dev/null | openssl x509 -noout -text" }),
  "adv.cookie-scope": (f) => ({ saw: clip(f.summary, 200), why: "Cookie gắn Domain rộng (cả tên miền con) hoặc sống rất lâu thì tên miền con khác đọc/ghi được và cookie bị lấy dùng được lâu.", consequence: "Một tên miền con yếu có thể đọc hoặc ghi đè cookie của trang chính.", steps: [S("dev", "Bỏ thuộc tính Domain cho cookie phiên và rút ngắn thời hạn.")], expect: "Cookie không còn Domain rộng.", certainty: "confirmed", caveat: CFG, verify: "curl -sI https://HOST/ | grep -i set-cookie" }),
  "adv.csp-analysis": (f) => ({ saw: clip(f.summary, 220), why: "Phân tích sâu CSP tìm các cách vượt qua chính sách (nguồn công cộng, thiếu base-uri/object-src).", consequence: "CSP có thể bị vượt trong tình huống có lỗi chèn mã.", steps: [S("dev", "Xử lý từng điểm yếu nêu trong bằng chứng, bắt đầu từ mức cao nhất.")], expect: "CSP không còn điểm yếu nêu ở trên.", certainty: "potential", caveat: "Khả năng vượt CSP còn tuỳ có lỗi chèn mã hay không; chúng tôi không thử.", verify: "curl -sI https://HOST/ | grep -i content-security-policy" }),
  "adv.shared-cache-leak": (f) => {
    const hit = key(f) === "hit";
    return { saw: clip(f.summary, 200), why: hit ? "Phản hồi có cookie nhưng lần gọi sau đã được cache dùng chung phục vụ lại: bằng chứng cache có thể lưu nội dung theo người dùng." : "Trang cho phép cache dùng chung nhưng lại đặt cookie.", consequence: hit ? "Người khác có thể nhận trang hoặc cookie của người trước." : "Nguy cơ tương tự nếu CDN lưu lại phản hồi có cookie.", steps: [S("host", "Đặt Cache-Control: private/no-store cho phản hồi có cookie hoặc cấu hình CDN bỏ qua cache khi có cookie.")], expect: "Phản hồi có cookie không còn được cache dùng chung.", certainty: hit ? "confirmed" : "potential", caveat: hit ? "Đã thấy phản hồi trúng cache; chưa chứng minh nội dung riêng của một người bị phát cho người khác." : "Chỉ là cấu hình cho phép.", verify: "curl -sI https://HOST/ | grep -i -E 'cache-control|age|x-cache'" };
  },
  "adv.supply-chain": (f) => ({ saw: clip(f.summary, 220), why: "Trang nạp script từ nguồn ngoài mà không kiểm soát nội dung; nếu nguồn bị chiếm, script độc chạy trên trang của bạn.", consequence: "Một nhà cung cấp bị xâm nhập có thể chèn mã vào mọi khách của bạn.", steps: [S("dev", "Tự lưu script cần thiết (self-host) hoặc gắn Subresource Integrity (integrity=\"sha384-…\") và bỏ nguồn lạ.")], expect: "Script ngoài có integrity hoặc được self-host.", certainty: "potential", caveat: "Rủi ro chuỗi cung ứng là xác suất, chưa chứng minh có script độc.", verify: "curl -s https://HOST/ | grep -o '<script[^>]*src=[^>]*>'" }),
  "adv.dom-xss-flow": (f) => ({ saw: clip(f.summary, 220), why: "Mã trên trang đọc dữ liệu từ URL (location, hash) rồi ghi vào các điểm nguy hiểm (innerHTML, eval).", consequence: "Nếu dữ liệu không được làm sạch, kẻ tấn công gửi liên kết độc để chạy mã trên trình duyệt khách (DOM XSS).", steps: [S("dev", "Kiểm tra từng chỗ ghi: dùng textContent thay innerHTML hoặc làm sạch dữ liệu bằng DOMPurify.")], expect: "Dữ liệu từ URL không đi thẳng vào innerHTML/eval.", certainty: "potential", caveat: "Đây là phân tích tĩnh theo mẫu mã, độ tin cậy thấp; chưa chứng minh dữ liệu thật sự đi từ nguồn tới điểm ghi mà không được làm sạch.", verify: "curl -s URL_JS | grep -n 'innerHTML'" }),
  "adv.postmessage": (f) => ({ saw: clip(f.summary, 220), why: "Mã dùng postMessage mà có vẻ không kiểm tra origin của người gửi/nhận.", consequence: "Trang lạ có thể gửi thông điệp giả hoặc nhận dữ liệu không dành cho họ.", steps: [S("dev", "Luôn kiểm tra event.origin trong handler và chỉ định origin đích cụ thể khi gửi (không dùng '*').")], expect: "Handler kiểm tra origin; gửi có origin đích cụ thể.", certainty: "potential", caveat: "Phân tích tĩnh độ tin cậy thấp; có thể đã kiểm tra origin ở chỗ chúng tôi không đọc.", verify: "curl -s URL_JS | grep -n 'postMessage\\|addEventListener(.message'" }),
  "adv.web-storage-secrets": (f) => ({ saw: clip(f.summary, 220), why: "Token hoặc khoá được lưu trong localStorage/sessionStorage; mọi script trên trang đọc được.", consequence: "Nếu có lỗi chèn mã, token bị lấy và dùng để vào tài khoản.", steps: [S("dev", "Lưu phiên trong cookie HttpOnly thay vì localStorage.")], expect: "Không còn token phiên trong bộ nhớ trình duyệt.", certainty: "potential", caveat: "Chỉ thấy mã ghi vào storage; chưa biết giá trị thật có nhạy cảm không.", verify: "curl -s URL_JS | grep -n 'localStorage'" }),
  "adv.endpoint-map": (f) => ({ saw: clip(f.summary, 220), why: "Danh sách endpoint rút từ mã giao diện công khai.", consequence: "Không phải lỗi. Cho thấy bề mặt cần kiểm tra quyền truy cập.", steps: [S("dev", "Đảm bảo mọi endpoint nhạy cảm kiểm tra đăng nhập và quyền phía máy chủ.")], expect: "Endpoint nhạy cảm yêu cầu xác thực.", certainty: "potential", caveat: "Chỉ liệt kê, không gọi thử.", verify: "curl -s URL_JS | grep -o '/api/[a-zA-Z0-9/_-]*' | sort -u" }),
  "adv.graphql-surface": (f) => ({ saw: clip(f.summary, 220), why: "Có endpoint GraphQL công khai. Nếu bật introspection, người ngoài đọc được toàn bộ lược đồ.", consequence: "Giúp dò tìm truy vấn nhạy cảm; rủi ro tuỳ vào việc kiểm soát quyền.", steps: [S("dev", "Tắt introspection ở production và giới hạn độ sâu truy vấn.")], expect: "Introspection trả lỗi ở production.", certainty: "potential", caveat: "Chúng tôi chỉ phát hiện endpoint, không thử truy vấn.", verify: "curl -s -X POST https://HOST/graphql -H 'content-type: application/json' -d '{\"query\":\"{__typename}\"}'" }),
  "adv.redirect-chain": (f) => ({ saw: clip(f.summary, 200), why: "Chuỗi chuyển hướng dài hoặc có bước hạ cấp xuống HTTP.", consequence: "Chậm hơn; bước HTTP là chỗ mất mã hoá.", steps: [S("host", "Rút gọn thành một bước và giữ HTTPS xuyên suốt.")], expect: "Một bước chuyển hướng HTTPS.", certainty: "confirmed", caveat: "Chỉ ảnh hưởng đường dẫn đã thử.", verify: "curl -sIL https://HOST/ | grep -i location" }),
  "adv.header-consistency": (f) => ({ saw: clip(f.summary, 200), why: "Header bảo mật có ở trang chủ nhưng thiếu ở các trang khác, thường do cấu hình chỉ áp cho một đường dẫn.", consequence: "Trang chưa có header vẫn bị tấn công như khi chưa có gì, nhất là trang đăng nhập.", steps: [S("host", "Đặt header ở mức toàn site (CDN/máy chủ), không đặt riêng từng trang.")], expect: "Mọi trang HTML cùng có header bảo mật.", certainty: "confirmed", caveat: "Chỉ mẫu vài trang đã kiểm tra, không phải toàn site.", verify: "for p in / /login; do curl -sI https://HOST$p | grep -ci content-security; done" }),
  "adv.spf-deep": (f) => ({ saw: clip(f.summary, 200), why: "Phân tích sâu SPF tìm điểm yếu (include rộng, vượt giới hạn, kết thúc lỏng).", consequence: "Thư mạo danh có thể vượt SPF.", steps: [S("dns", "Xử lý từng điểm yếu theo bằng chứng.")], expect: "SPF chặt, dưới 10 truy vấn.", certainty: "confirmed", caveat: "Kết quả từ DNS công khai; chúng tôi không biết tên miền có gửi email hay không.", verify: `dig +short TXT ${"HOST"}` }),
  "adv.dmarc-deep": (f) => ({ saw: clip(f.summary, 200), why: "DMARC có nhưng chưa thực thi đầy đủ (p=none, thiếu rua, sp lỏng…).", consequence: "Thư mạo danh vẫn có thể tới hộp thư.", steps: [S("dns", "Nâng dần chính sách tới quarantine rồi reject; thêm rua để nhận báo cáo.")], expect: "DMARC p=quarantine/reject kèm rua.", certainty: "confirmed", caveat: "Kết quả từ DNS công khai.", verify: "dig +short TXT _dmarc.HOST" }),
  "adv.form-method": () => ({ saw: "Một form có ô mật khẩu gửi bằng GET.", why: "GET đưa dữ liệu vào URL nên mật khẩu nằm trong lịch sử trình duyệt và nhật ký máy chủ.", consequence: "Mật khẩu có thể nằm lại trong nhật ký.", steps: [S("dev", "Đổi sang method=\"post\".")], expect: "Form dùng POST.", certainty: "confirmed", caveat: "Đã thấy trong HTML; chưa xác nhận nhật ký thực tế.", verify: "curl -s https://HOST/ | grep -i '<form'" }),
};
