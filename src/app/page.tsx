import Link from "next/link";
import { ScanForm } from "@/components/ScanForm";
import { ScoreRing } from "@/components/motion/ScoreRing";
import { getUser } from "@/lib/auth/next";
import { demoBeforeReport } from "@/lib/demo";
import { SEV_CHIP } from "@/lib/format";
import { CATEGORY_LABEL, SEV_LABEL } from "@/lib/i18n";
import { ALL_RULES } from "@/lib/scanner/rules";
import { CATEGORIES } from "@/lib/scanner/types";

const CHECKS: Record<(typeof CATEGORIES)[number], string> = {
  "Transport Security": "HTTPS và chứng chỉ, phiên bản TLS, HTTP/2, chuyển hướng HTTP→HTTPS, HSTS, biểu mẫu nhập mật khẩu.",
  Headers: "Content-Security-Policy, chống clickjacking, nosniff, header sai định dạng, COOP/CORP/COEP.",
  "Browser Security": "Nội dung hỗn hợp (mixed content), script CDN thiếu kiểm tra toàn vẹn, cấu hình CORS.",
  "Cookies & Sessions": "Cờ Secure, HttpOnly, SameSite, tiền tố __Host-, thời hạn cookie phiên, cache trang đăng nhập.",
  Exposure: "Khoá bí mật trong JS, source map, thư viện lỗi thời (CVE), nguy cơ chiếm subdomain, trang lỗi lộ thông tin.",
  Configuration: "Lộ phiên bản máy chủ, chuyển hướng đáng ngờ, SPF/DMARC/CAA, DNSSEC, MTA-STS.",
  Privacy: "Referrer-Policy, Permissions-Policy, tài nguyên và trình theo dõi của bên thứ ba.",
};

const STEPS = [
  { n: "01", t: "Dán một URL", d: "Chỉ cần tên miền. Chúng tôi chuẩn hoá và chặn mọi địa chỉ nội bộ ngay từ đầu." },
  { n: "02", t: "Quét thụ động", d: "Chín giai đoạn: phân giải, TLS, header, endpoint công khai, rủi ro phía trình duyệt, cấu hình, chấm điểm." },
  { n: "03", t: "Nhận báo cáo & cách sửa", d: "Điểm 0–100, bằng chứng cụ thể và cấu hình sao chép được cho đúng hệ thống của bạn." },
];

export default async function Home() {
  const user = await getUser();
  const demo = demoBeforeReport();
  const risks = demo.findings.filter((f) => f.status === "fail" && f.severity !== "info").slice(0, 4);

  return (
    <>
      {/* ---- hero */}
      <section className="relative overflow-hidden">
        <div aria-hidden className="bg-grid pointer-events-none absolute inset-0 -z-10" />
        <div className="container-x pb-20 pt-16 sm:pb-28 sm:pt-24">
          <p className="reveal eyebrow flex items-center gap-2"><span className="live-dot" aria-hidden />kiểm tra bảo mật từ bên ngoài · thụ động · không phá hoại</p>
          <h1 className="reveal mt-5 max-w-4xl text-[2.6rem] font-semibold leading-[1.04] tracking-tight sm:text-6xl lg:text-7xl" style={{ ["--i" as string]: 1 }}>
            Biết trước <span className="text-accent">kẻ tấn công thấy gì</span> ở website của bạn.
          </h1>
          <p className="reveal mt-6 max-w-2xl text-lg leading-relaxed text-muted" style={{ ["--i" as string]: 2 }}>
            Dán một URL. VibeSec chạy {ALL_RULES.length} kiểm tra thụ động, chấm điểm cấu hình trên thang 100 và chỉ ra cách khắc phục cụ thể cho từng vấn đề — bằng tiếng Việt dễ hiểu, không cần kiến thức bảo mật.
          </p>
          <div className="reveal mt-10 max-w-3xl" style={{ ["--i" as string]: 3 }}><ScanForm authed={!!user} /></div>
          <p className="reveal mt-4 flex flex-wrap items-center gap-x-5 gap-y-1.5 text-sm text-muted" style={{ ["--i" as string]: 4 }}>
            <span className="flex items-center gap-1.5"><Tick />Không khai thác lỗ hổng</span>
            <span className="flex items-center gap-1.5"><Tick />Không dò mật khẩu</span>
            <span className="flex items-center gap-1.5"><Tick />Không thu thập toàn bộ website</span>
            {!user && <span className="text-faint">· Cần tài khoản miễn phí để chống lạm dụng</span>}
          </p>
        </div>
      </section>

      {/* ---- cách hoạt động */}
      <section className="hairline" aria-labelledby="how">
        <div className="container-x py-20">
          <h2 id="how" className="eyebrow">cách hoạt động</h2>
          <ol className="mt-8 grid gap-10 md:grid-cols-3">
            {STEPS.map((s, i) => (
              <li key={s.n} className="reveal" style={{ ["--i" as string]: i }}>
                <p className="mono text-sm font-medium text-accent">{s.n}</p>
                <h3 className="mt-2 text-xl font-semibold tracking-tight">{s.t}</h3>
                <p className="mt-2 text-[15px] leading-relaxed text-muted">{s.d}</p>
              </li>
            ))}
          </ol>
        </div>
      </section>

      {/* ---- báo cáo mẫu */}
      <section className="hairline bg-surface/60" aria-labelledby="example">
        <div className="container-x grid items-center gap-12 py-20 lg:grid-cols-[1fr_1.15fr] lg:gap-20">
          <div>
            <h2 id="example" className="text-3xl font-semibold tracking-tight sm:text-4xl">Báo cáo giúp bạn hành động ngay</h2>
            <p className="mt-4 max-w-lg text-[15px] leading-relaxed text-muted">Mỗi phát hiện nêu rõ chúng tôi thấy gì, tác động tiềm ẩn, bằng chứng và cấu hình có thể sao chép cho đúng hệ thống của bạn — hoặc hướng dẫn chung khi chưa xác định được bạn dùng gì. Chúng tôi không bao giờ tự bịa cấu hình.</p>
            <Link href="/demo" className="btn-dark mt-8">Xem báo cáo demo đầy đủ<svg viewBox="0 0 24 24" className="size-4" fill="none" stroke="currentColor" strokeWidth="2.2" strokeLinecap="round" strokeLinejoin="round" aria-hidden><path d="M5 12h14M13 6l6 6-6 6" /></svg></Link>
          </div>
          <div className="panel overflow-hidden" aria-label="Xem trước báo cáo mẫu">
            <div className="term-bar"><span className="term-dot" /><span className="term-dot" /><span className="term-dot" /><span className="mono ml-1">{demo.host}</span></div>
            <div className="grid items-center gap-6 p-6 sm:grid-cols-[auto_1fr]">
              <ScoreRing score={demo.score} grade={demo.grade} size={132} />
              <ul className="space-y-2.5 text-sm">
                {risks.map((f) => (
                  <li key={f.fingerprint} className="flex items-start gap-2.5"><span className={`${SEV_CHIP[f.severity]} mt-0.5 shrink-0`}>{SEV_LABEL[f.severity]}</span><span className="leading-snug">{f.title}</span></li>
                ))}
              </ul>
            </div>
          </div>
        </div>
      </section>

      {/* ---- những gì kiểm tra */}
      <section id="checks" className="hairline" aria-labelledby="checks-h">
        <div className="container-x py-20">
          <div className="flex flex-wrap items-end justify-between gap-4">
            <h2 id="checks-h" className="text-3xl font-semibold tracking-tight sm:text-4xl">Những gì chúng tôi kiểm tra</h2>
            <Link href="/phuong-phap" className="text-sm font-medium text-accent hover:underline">Phương pháp chấm điểm &amp; danh sách {ALL_RULES.length} kiểm tra →</Link>
          </div>
          <dl className="mt-10 divide-y divide-line border-y border-line">
            {CATEGORIES.map((c, i) => (
              <div key={c} className="reveal grid gap-1 py-5 md:grid-cols-[16rem_1fr] md:gap-8" style={{ ["--i" as string]: i }}>
                <dt className="flex items-baseline gap-3 font-medium"><span className="mono text-xs text-faint">{String(i + 1).padStart(2, "0")}</span>{CATEGORY_LABEL[c]}</dt>
                <dd className="text-[15px] leading-relaxed text-muted">{CHECKS[c]}</dd>
              </div>
            ))}
          </dl>
        </div>
      </section>

      {/* ---- an toàn */}
      <section className="hairline bg-surface/60" aria-labelledby="safe-h">
        <div className="container-x grid gap-12 py-20 md:grid-cols-2">
          <div>
            <h2 id="safe-h" className="text-3xl font-semibold tracking-tight sm:text-4xl">An toàn ngay từ thiết kế</h2>
            <p className="mt-4 max-w-md text-[15px] leading-relaxed text-muted">VibeSec chỉ xem những gì trình duyệt của bất kỳ khách truy cập nào cũng thấy. Kết quả mang tính xác định — không dùng AI đoán mò — và công cụ quét được xây để không thể bị lợi dụng truy cập hạ tầng nội bộ.</p>
          </div>
          <ul className="space-y-3.5 text-[15px] text-muted">
            {[
              "Không dò mật khẩu, không gửi mã khai thác, không SQL/XSS/command injection hay fuzzing.",
              "Chỉ quét website công khai trên cổng 80/443; mạng nội bộ và metadata đám mây bị chặn ở nhiều lớp, kể cả DNS rebinding và chuyển hướng.",
              "Số yêu cầu nhỏ và cố định tới trang chủ cùng vài tệp công khai.",
              "Tự nhận diện là VibeSecBot; không lưu nội dung trang, khoá bí mật nếu phát hiện được che ngay lập tức.",
              "Giới hạn tần suất theo tài khoản, địa chỉ mạng và từng website đích.",
            ].map((t) => <li key={t} className="flex gap-3"><Tick />{t}</li>)}
          </ul>
        </div>
      </section>
    </>
  );
}

function Tick() {
  return <svg viewBox="0 0 24 24" className="mt-0.5 size-4 shrink-0 text-ok" fill="none" stroke="currentColor" strokeWidth="2.6" strokeLinecap="round" strokeLinejoin="round" aria-hidden><path d="m5 12.5 4.5 4.5L19 7.5" /></svg>;
}
