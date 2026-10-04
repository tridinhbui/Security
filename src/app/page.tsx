import Link from "next/link";
import { ScanForm } from "@/components/ScanForm";
import { demoBeforeReport } from "@/lib/demo";
import { gradeColor, scoreColor, SEV_COLOR, SEV_LABEL } from "@/lib/format";
import { CATEGORY_LABEL } from "@/lib/i18n";
import { CATEGORIES } from "@/lib/scanner/types";
import { getUser } from "@/lib/auth/next";

const CHECKS: Record<(typeof CATEGORIES)[number], string> = {
  "Transport Security": "Khả năng truy cập HTTPS, phiên bản TLS và chứng chỉ, chuyển hướng HTTP→HTTPS, HSTS, biểu mẫu nhập mật khẩu.",
  Headers: "Content-Security-Policy, chống clickjacking, X-Content-Type-Options, các header sai định dạng hoặc mâu thuẫn nhau.",
  "Browser Security": "Nội dung hỗn hợp (mixed content), script bên thứ ba không có kiểm tra tính toàn vẹn, cấu hình CORS.",
  "Cookies & Sessions": "Các cờ Secure, HttpOnly và SameSite của cookie xuất hiện trong phản hồi; việc lưu đệm (cache) các trang đăng nhập.",
  Exposure: "Source map, khoá bí mật trong JavaScript công khai, giá trị biến môi trường phía trình duyệt, robots.txt, sitemap.xml, security.txt.",
  Configuration: "Header lộ phiên bản máy chủ/framework, chuyển hướng đáng ngờ, SPF/DMARC/CAA, dấu vết công nghệ sử dụng.",
  Privacy: "Referrer-Policy, Permissions-Policy, các yêu cầu tới bên thứ ba có thể nhìn thấy khách truy cập của bạn.",
};

export default async function Home() {
  const user = await getUser();
  const demo = demoBeforeReport();
  const risks = demo.findings.filter((f) => f.status === "fail" && f.severity !== "info").slice(0, 3);

  return (
    <>
      <section className="mx-auto max-w-5xl px-5 pt-16 sm:pt-24 pb-16">
        <p className="text-sm text-muted mb-4">Kiểm tra bảo mật website từ bên ngoài</p>
        <h1 className="text-4xl sm:text-6xl font-semibold tracking-tight leading-[1.05] max-w-3xl">
          Xem website của bạn đang để lộ những gì, bằng ngôn ngữ dễ hiểu.
        </h1>
        <p className="mt-6 text-lg text-muted max-w-2xl">
          Dán một URL. VibeSec sẽ chạy các kiểm tra thụ động, chấm điểm cấu hình của bạn trên thang 100 và chỉ ra cách khắc phục cụ thể cho từng vấn đề. Không cần kiến thức bảo mật.
        </p>
        <div className="mt-10 max-w-3xl"><ScanForm authed={!!user} /></div>
        <p className="mt-4 text-sm text-muted max-w-3xl">
          Không phá hoại: chỉ vài yêu cầu trang thông thường, không khai thác lỗ hổng, không dò mật khẩu, không thu thập toàn bộ website. {user ? "" : "Cần có tài khoản miễn phí để tránh bị lạm dụng công cụ quét."}
        </p>
      </section>

      <section className="border-t border-line" aria-labelledby="example">
        <div className="mx-auto max-w-5xl px-5 py-16 grid gap-10 lg:grid-cols-[1fr_1.1fr] lg:gap-16 items-start">
          <div>
            <h2 id="example" className="text-2xl font-semibold tracking-tight">Báo cáo giúp bạn hành động ngay</h2>
            <p className="mt-3 text-muted">Mỗi phát hiện đều giải thích chúng tôi thấy gì, vì sao điều đó quan trọng, kèm bằng chứng và cấu hình có thể sao chép cho đúng hệ thống của bạn, hoặc hướng dẫn chung khi chưa xác định được bạn đang dùng gì. Chúng tôi không bao giờ tự bịa ra cấu hình.</p>
            <Link href="/demo" className="inline-block mt-6 text-sm underline underline-offset-4 hover:text-fg text-muted">Xem báo cáo demo đầy đủ →</Link>
          </div>
          <div className="border border-line rounded-lg p-5 sm:p-6 bg-surface" aria-label="Xem trước báo cáo mẫu">
            <div className="flex items-end justify-between gap-4">
              <div>
                <p className="text-xs text-muted">{demo.host}</p>
                <p className={`num text-6xl font-semibold tracking-tighter leading-none mt-1 ${scoreColor(demo.score)}`}>{demo.score}</p>
              </div>
              <p className={`text-4xl font-semibold ${gradeColor(demo.grade)}`}>{demo.grade}</p>
            </div>
            <ul className="mt-6 divide-y divide-line text-sm">
              {risks.map((f) => (
                <li key={f.fingerprint} className="py-2.5 flex gap-3">
                  <span className={`w-14 shrink-0 text-xs font-semibold uppercase mt-0.5 ${SEV_COLOR[f.severity]}`}>{SEV_LABEL[f.severity]}</span>
                  <span>{f.title}</span>
                </li>
              ))}
            </ul>
            <div className="mt-5 grid grid-cols-2 gap-x-6 gap-y-2 text-xs text-muted">
              {CATEGORIES.slice(0, 4).map((c) => (
                <div key={c} className="flex justify-between"><span>{CATEGORY_LABEL[c]}</span><span className={`num ${scoreColor(demo.categoryScores[c] ?? null)}`}>{demo.categoryScores[c] ?? "—"}</span></div>
              ))}
            </div>
          </div>
        </div>
      </section>

      <section id="checks" className="border-t border-line" aria-labelledby="checks-h">
        <div className="mx-auto max-w-5xl px-5 py-16">
          <h2 id="checks-h" className="text-2xl font-semibold tracking-tight">Những gì chúng tôi kiểm tra</h2>
          <dl className="mt-8 grid gap-x-16 gap-y-6 md:grid-cols-2">
            {CATEGORIES.map((c) => (
              <div key={c}><dt className="font-medium">{CATEGORY_LABEL[c]}</dt><dd className="text-muted text-[15px] mt-1">{CHECKS[c]}</dd></div>
            ))}
          </dl>
          <p className="mt-8 text-sm"><Link href="/phuong-phap" className="underline underline-offset-4 text-muted hover:text-fg">Phương pháp chấm điểm &amp; danh sách kiểm tra</Link></p>
        </div>
      </section>

      <section className="border-t border-line" aria-labelledby="safe-h">
        <div className="mx-auto max-w-5xl px-5 py-16 grid gap-10 md:grid-cols-2">
          <div>
            <h2 id="safe-h" className="text-2xl font-semibold tracking-tight">An toàn ngay từ thiết kế</h2>
            <p className="mt-3 text-muted">VibeSec chỉ xem những gì trình duyệt của bất kỳ khách truy cập nào cũng thấy được. Kết quả mang tính xác định, không dùng AI đoán mò, và không bao giờ động vào những thứ không được phép.</p>
          </div>
          <ul className="space-y-2.5 text-[15px] text-muted">
            {[
              "Không dò mật khẩu, không gửi mã khai thác, không SQL/XSS/command injection hay fuzzing.",
              "Chỉ quét website công khai trên cổng 80/443; mạng nội bộ và metadata đám mây đều bị chặn.",
              "Số lượng yêu cầu nhỏ và cố định tới trang chủ cùng một vài tệp cùng nguồn gốc.",
              "Tự nhận diện là VibeSecBot; không lưu toàn bộ nội dung trang và các thông tin bí mật đều được che đi.",
              "Có giới hạn tần suất và thời gian chờ cho từng website để không thể dùng làm công cụ gây quá tải.",
            ].map((t) => <li key={t} className="flex gap-3"><span className="text-ok mt-0.5" aria-hidden>✓</span>{t}</li>)}
          </ul>
        </div>
      </section>
    </>
  );
}
