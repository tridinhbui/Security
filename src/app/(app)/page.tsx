import Link from "next/link";
import { redirect } from "next/navigation";
import { HeroVisual } from "@/components/HeroVisual";
import { HeroStage } from "@/components/landing/HeroStage";
import { Reveal } from "@/components/landing/Reveal";
import { SplitText } from "@/components/landing/SplitText";
import { Faq, FinalCta, ProjectScans, Trust } from "@/components/landing/TrustSections";
import { AnimatedNumber } from "@/components/motion/AnimatedNumber";
import { MatMatSays } from "@/components/matmat/MatMatSays";
import { ScanForm } from "@/components/ScanForm";
import { getUser } from "@/lib/auth/next";
import { CATEGORY_LABEL } from "@/lib/i18n";
import { ALL_RULES } from "@/lib/scanner/rules";
import { LiveStats } from "@/components/landing/LiveStats";
import { publicStats } from "@/lib/db/stats-repo";
import { getDb } from "@/lib/cf";
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
  { n: "02", t: "Chỉ xem, không động vào website", d: "VibeSec chỉ xem những gì ai cũng thấy được và không thay đổi gì trên website của bạn." },
  { n: "03", t: "Biết sửa gì trước, ai sửa, sửa ra sao", d: "Mỗi vấn đề có lời giải thích tiếng Việt, mức ưu tiên, người cần làm (lập trình viên, hosting hay người quản lý tên miền), các bước sửa và cách tự kiểm tra lại." },
];

export default async function Home() {
  const user = await getUser();
  if (user) redirect("/dashboard"); // đã đăng nhập thì vào khu làm việc, không hiện trang giới thiệu lẫn trong sidebar
  const stats = await publicStats(await getDb()).catch(() => null); // số thật lúc tải trang; LiveStats tự làm mới sau đó

  return (
    <>
      {/* ---- hero */}
      <HeroStage className="hero-glow">
        <div aria-hidden className="hero-orbs"><span className="orb orb-a" /><span className="orb orb-b" /><span className="orb orb-c" /><span className="cursor-glow" /></div>
        {/* Hero vừa đúng một màn hình (trừ thanh điều hướng): tiêu đề → thanh quét dài → hai cột: Mật Mật (trái) | số liệu trực tiếp (phải). Hình minh hoạ chuyển xuống dưới. */}
        <div className="container-x relative flex min-h-[calc(100svh-4rem)] flex-col items-center justify-center gap-7 py-10 text-center sm:py-12">
          <div className="depth-copy flex w-full flex-col items-center">
            <p className="reveal eyebrow">kiểm tra bảo mật website · không cần biết kỹ thuật</p>
            <h1 className="mt-5 text-[2.5rem] font-semibold leading-[1.02] tracking-[-0.035em] sm:text-[3.8rem]">
              <SplitText lines={[[{ text: "Website của bạn" }], [{ text: "đang hở chỗ nào?", className: "headline-live" }]]} />
            </h1>
            <p className="reveal mt-5 max-w-xl text-balance text-[16px] leading-[1.7] text-muted" style={{ ["--i" as string]: 2 }}>
              Dán địa chỉ website, VibeSec chỉ ra chỗ nào chưa an toàn và hướng dẫn sửa từng bước bằng tiếng Việt dễ hiểu.
            </p>
            <div className="reveal mt-7 w-full max-w-[880px] text-left" style={{ ["--i" as string]: 3 }}><ScanForm authed={!!user} label={user ? undefined : "Quét miễn phí"} /></div>
            <p className="reveal mt-3 text-sm text-faint" style={{ ["--i" as string]: 4 }}><AnimatedNumber value={ALL_RULES.length} delay={700} /> kiểm tra bảo mật{!user ? " · Quét nhanh không cần tài khoản" : ""}</p>
          </div>
          <div className="grid w-full max-w-[880px] items-stretch gap-4 text-left md:grid-cols-2">
            <div className="flex flex-col justify-center rounded-2xl border border-line bg-white/70 p-4 shadow-crisp backdrop-blur">
              <MatMatSays text="Mình là Mật Mật 🐾 Mình sẽ đi xem website của bạn giống như một người khách tò mò, rồi kể lại cho bạn nghe thật dễ hiểu: chỗ nào chưa khoá cửa và nên sửa thế nào. Không cần biết kỹ thuật đâu!" />
              {!user && <p className="mt-3 text-xs text-faint">Tạo tài khoản miễn phí để quét đầy đủ và lưu lịch sử.</p>}
            </div>
            <LiveStats initial={stats} />
          </div>
        </div>
      </HeroStage>

      {/* ---- cách hoạt động: hình minh hoạ bên trái, ba bước bên phải (một khối duy nhất) */}
      <section className="hairline" aria-labelledby="how">
        <div className="container-x grid items-center gap-10 py-14 lg:grid-cols-[1fr_1fr] lg:gap-16">
          <div className="mx-auto w-full max-w-xl" aria-label="Minh hoạ lượt quét"><HeroVisual total={ALL_RULES.length} /></div>
          <div>
            <p className="eyebrow mb-3">cách hoạt động</p>
            <h2 id="how" className="text-3xl font-semibold tracking-tight sm:text-4xl">Ba bước, không cần biết kỹ thuật.</h2>
            <ol className="mt-8 space-y-7">
              {STEPS.map((s, i) => (
                <li key={s.n}>
                  <Reveal delay={i * 110} className="step-item flex items-start gap-4">
                    <span className="step-n mono grid size-9 shrink-0 place-items-center rounded-full bg-accent-soft text-sm font-semibold text-accent">{s.n}</span>
                    <span><span className="block text-lg font-semibold tracking-tight">{s.t}</span><span className="mt-1 block text-[15px] leading-relaxed text-muted">{s.d}</span></span>
                  </Reveal>
                </li>
              ))}
            </ol>
          </div>
        </div>
      </section>

      {/* ---- những gì kiểm tra */}
      <section id="checks" className="hairline" aria-labelledby="checks-h">
        <div className="container-x py-14">
          <Reveal className="flex flex-wrap items-end justify-between gap-4">
            <div><p className="eyebrow mb-3">{ALL_RULES.length} kiểm tra bảo mật</p><h2 id="checks-h" className="text-3xl font-semibold tracking-tight sm:text-4xl">Kiểm tra toàn diện từ hạ tầng đến mã nguồn.</h2></div>
            <div className="flex flex-wrap items-center gap-x-5 gap-y-2"><Link href="/demo" className="btn-dark btn-sm">Xem báo cáo demo →</Link><Link href="/phuong-phap" className="text-sm font-medium text-accent hover:underline">Chi tiết phương pháp →</Link></div>
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

      <ProjectScans />
      <Trust />
      <Faq />
      <FinalCta />
    </>
  );
}

function Tick() {
  return <svg viewBox="0 0 24 24" className="mt-0.5 size-4 shrink-0 text-ok" fill="none" stroke="currentColor" strokeWidth="2.6" strokeLinecap="round" strokeLinejoin="round" aria-hidden><path d="m5 12.5 4.5 4.5L19 7.5" /></svg>;
}
