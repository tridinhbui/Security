import Link from "next/link";
import { redirect } from "next/navigation";
import { HeroVisual } from "@/components/HeroVisual";
import { HeroStage } from "@/components/landing/HeroStage";
import { Reveal } from "@/components/landing/Reveal";
import { SplitText } from "@/components/landing/SplitText";
import { TiltCard } from "@/components/landing/TiltCard";
import { AnimatedNumber } from "@/components/motion/AnimatedNumber";
import { MatMatSays } from "@/components/matmat/MatMatSays";
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

const ICONS: Record<(typeof CATEGORIES)[number], React.ReactNode> = {
  "Transport Security": <><rect x="5" y="11" width="14" height="9" rx="2" /><path d="M8 11V8a4 4 0 0 1 8 0v3" /></>,
  Headers: <><rect x="4" y="5" width="16" height="14" rx="2" /><path d="M4 9h16M7 7h.01" /></>,
  "Browser Security": <><path d="m12 3 8 4-8 4-8-4 8-4Z" /><path d="m4 12 8 4 8-4M4 16.5l8 4 8-4" /></>,
  "Cookies & Sessions": <><circle cx="12" cy="12" r="8" /><path d="M9 10h.01M14 9h.01M10 15h.01M15 14h.01" /></>,
  Exposure: <><path d="M14 3H7a2 2 0 0 0-2 2v14a2 2 0 0 0 2 2h10a2 2 0 0 0 2-2V8l-5-5Z" /><path d="M9 13h6M9 17h4" /></>,
  Configuration: <><circle cx="12" cy="12" r="3" /><path d="M12 3v3M12 18v3M3 12h3M18 12h3M5.6 5.6l2.1 2.1M16.3 16.3l2.1 2.1M18.4 5.6l-2.1 2.1M7.7 16.3l-2.1 2.1" /></>,
  Privacy: <><path d="M2.5 12S6 5.5 12 5.5 21.5 12 21.5 12 18 18.5 12 18.5 2.5 12 2.5 12Z" /><circle cx="12" cy="12" r="2.5" /></>,
};

const STEPS = [
  { n: "01", t: "Dán một URL", d: "Chỉ cần tên miền. Chúng tôi chuẩn hoá và chặn mọi địa chỉ nội bộ ngay từ đầu." },
  { n: "02", t: "Quét thụ động", d: "Chín giai đoạn: phân giải, TLS, header, endpoint công khai, rủi ro phía trình duyệt, cấu hình, chấm điểm." },
  { n: "03", t: "Nhận báo cáo & cách sửa", d: "Điểm 0–100, bằng chứng cụ thể và cấu hình sao chép được cho đúng hệ thống của bạn." },
];

export default async function Home() {
  const user = await getUser();
  if (user) redirect("/dashboard"); // đã đăng nhập thì vào khu làm việc, không hiện trang giới thiệu lẫn trong sidebar
  const demo = demoBeforeReport();
  const risks = demo.findings.filter((f) => f.status === "fail" && f.severity !== "info").slice(0, 4);

  return (
    <>
      {/* ---- hero */}
      <HeroStage className="hero-glow">
        <div aria-hidden className="hero-orbs"><span className="orb orb-a" /><span className="orb orb-b" /><span className="orb orb-c" /><span className="cursor-glow" /></div>
        <div className="container-x relative grid items-center gap-8 pb-16 pt-14 sm:pt-20 lg:grid-cols-[1.05fr_1fr] lg:pb-24">
          <div className="depth-copy">
            <p className="reveal eyebrow">external attack surface scanner</p>
            <h1 className="mt-7 text-[2.8rem] font-semibold leading-[1.02] tracking-[-0.035em] sm:text-[4.2rem]">
              <SplitText lines={[[{ text: "Nhìn website" }], [{ text: "như một attacker.", className: "headline-live" }]]} />
            </h1>
            <p className="reveal mt-7 max-w-xl text-[17px] leading-[1.8] text-muted" style={{ ["--i" as string]: 2 }}>
              VibeSec tự động chạy {ALL_RULES.length} kiểm tra bảo mật, phân tích bề mặt tấn công công khai của bất kỳ website nào, và hướng dẫn cách khắc phục — đơn giản, rõ ràng, không cần kiến thức chuyên sâu.
            </p>
            <div className="reveal mt-9 max-w-[640px]" style={{ ["--i" as string]: 3 }}><ScanForm authed={!!user} /></div>
            <ul className="reveal mt-6 flex flex-wrap gap-3" style={{ ["--i" as string]: 4 }}>
              <li className="pill"><span className="size-2 rounded-full bg-ok" /><span><AnimatedNumber value={ALL_RULES.length} delay={700} /> kiểm tra bảo mật</span></li>
              <li className="pill"><span className="size-2 rounded-full bg-accent" />Chỉ thu thập thông tin công khai</li>
              <li className="pill"><span className="size-2 rounded-full bg-faint" />Không khai thác lỗ hổng</li>
            </ul>
            <MatMatSays className="mt-6 max-w-xl" text="Mình là Mật Mật 🐾 Mình sẽ đi xem website của bạn giống như một người khách tò mò, rồi kể lại cho bạn nghe thật dễ hiểu: chỗ nào chưa khoá cửa và nên sửa thế nào. Không cần biết kỹ thuật đâu!" />
            {!user && <p className="mt-4 text-sm text-faint">Cần tài khoản miễn phí để chống lạm dụng.</p>}
          </div>
          <HeroVisual />
        </div>
      </HeroStage>

      {/* ---- cách hoạt động (dải ngắn) */}
      <section className="hairline" aria-labelledby="how">
        <div className="container-x py-10">
          <h2 id="how" className="sr-only">Cách hoạt động</h2>
          <ol className="grid gap-6 md:grid-cols-3 md:gap-10">
            {STEPS.map((s, i) => (
              <li key={s.n}>
                <Reveal delay={i * 110} className="step-item flex items-start gap-4">
                  <span className="step-n mono grid size-9 shrink-0 place-items-center rounded-full bg-accent-soft text-sm font-semibold text-accent">{s.n}</span>
                  <span><span className="block font-semibold tracking-tight">{s.t}</span><span className="mt-1 block text-sm leading-relaxed text-muted">{s.d}</span></span>
                </Reveal>
              </li>
            ))}
          </ol>
        </div>
      </section>

      {/* ---- những gì kiểm tra */}
      <section id="checks" className="hairline" aria-labelledby="checks-h">
        <div className="container-x py-14">
          <Reveal className="flex flex-wrap items-end justify-between gap-4">
            <div><p className="eyebrow mb-3">{ALL_RULES.length} kiểm tra bảo mật</p><h2 id="checks-h" className="text-3xl font-semibold tracking-tight sm:text-4xl">Kiểm tra toàn diện từ hạ tầng đến mã nguồn.</h2></div>
            <Link href="/phuong-phap" className="text-sm font-medium text-accent hover:underline">Xem chi tiết phương pháp →</Link>
          </Reveal>
          <div className="mt-9 grid gap-x-8 gap-y-9 sm:grid-cols-2 lg:grid-cols-4">
            {CATEGORIES.map((c, i) => (
              <Reveal key={c} delay={(i % 4) * 90} className="check-card border-l border-line pl-6 first:border-l-0 first:pl-0 sm:[&:nth-child(2n+1)]:border-l-0 sm:[&:nth-child(2n+1)]:pl-0 lg:[&:nth-child(2n+1)]:border-l lg:[&:nth-child(2n+1)]:pl-6 lg:[&:nth-child(4n+1)]:border-l-0 lg:[&:nth-child(4n+1)]:pl-0">
                <svg viewBox="0 0 24 24" className="size-6 text-fg" fill="none" stroke="currentColor" strokeWidth="1.5" strokeLinecap="round" strokeLinejoin="round" aria-hidden>{ICONS[c]}</svg>
                <h3 className="mt-5 text-[15px] font-semibold">{CATEGORY_LABEL[c]}</h3>
                <p className="mt-2 text-[14px] leading-relaxed text-muted">{CHECKS[c]}</p>
                <div className="bars mt-5" aria-hidden>{Array.from({ length: 16 }, (_, k) => <i key={k} className={k < 3 + ((i * 5 + 4) % 7) ? "on" : ""} style={{ height: `${8 + ((k * 7 + i * 3) % 14)}px`, ["--k" as string]: k }} />)}</div>
              </Reveal>
            ))}
          </div>
        </div>
      </section>

      {/* ---- báo cáo mẫu + an toàn (gộp) */}
      <section className="hairline bg-surface/60" aria-labelledby="example">
        <div className="container-x grid items-center gap-10 py-14 lg:grid-cols-2 lg:gap-16">
          <Reveal from="left"><TiltCard className="panel overflow-hidden" >
            <div role="group" aria-label="Xem trước báo cáo mẫu">
            <div className="term-bar"><span className="term-dot" /><span className="term-dot" /><span className="term-dot" /><span className="mono ml-1">{demo.host}</span></div>
            <div className="grid items-center gap-5 p-5 sm:grid-cols-[auto_1fr]">
              <ScoreRing score={demo.score} grade={demo.grade} size={112} />
              <ul className="space-y-2 text-sm">
                {risks.slice(0, 3).map((f) => (
                  <li key={f.fingerprint} className="flex items-start gap-2.5"><span className={`${SEV_CHIP[f.severity]} mt-0.5 shrink-0`}>{SEV_LABEL[f.severity]}</span><span className="leading-snug">{f.title}</span></li>
                ))}
              </ul>
            </div>
            </div>
          </TiltCard></Reveal>
          <Reveal from="right" delay={120}>
            <h2 id="example" className="text-2xl font-semibold tracking-tight sm:text-3xl">Báo cáo dễ hiểu, an toàn ngay từ thiết kế</h2>
            <ul className="mt-5 space-y-2.5 text-[15px] text-muted">
              {["Chỉ xem những gì ai cũng thấy được: không dò mật khẩu, không gửi mã khai thác.", "Chỉ quét website công khai; mạng nội bộ bị chặn nhiều lớp.", "Mỗi vấn đề có lời giải thích đơn giản và prompt dán thẳng vào AI để sửa."].map((t) => <li key={t} className="flex gap-3"><Tick />{t}</li>)}
            </ul>
            <Link href="/demo" className="btn-dark mt-7">Xem báo cáo demo<svg viewBox="0 0 24 24" className="size-4" fill="none" stroke="currentColor" strokeWidth="2.2" strokeLinecap="round" strokeLinejoin="round" aria-hidden><path d="M5 12h14M13 6l6 6-6 6" /></svg></Link>
          </Reveal>
        </div>
      </section>
    </>
  );
}

function Tick() {
  return <svg viewBox="0 0 24 24" className="mt-0.5 size-4 shrink-0 text-ok" fill="none" stroke="currentColor" strokeWidth="2.6" strokeLinecap="round" strokeLinejoin="round" aria-hidden><path d="m5 12.5 4.5 4.5L19 7.5" /></svg>;
}
