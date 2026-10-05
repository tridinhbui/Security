import type { Metadata, Viewport } from "next";
import Link from "next/link";
import "./globals.css";
import { SiteHeader } from "@/components/SiteHeader";

export const metadata: Metadata = {
  title: { default: "VibeSec — kiểm tra bảo mật website bằng ngôn ngữ dễ hiểu", template: "%s · VibeSec" },
  description: "Dán một URL để nhận báo cáo bảo mật rõ ràng, dễ hiểu. Chỉ kiểm tra thụ động, không phá hoại, kèm cách khắc phục cụ thể.",
  robots: { index: true, follow: true },
};
export const viewport: Viewport = { themeColor: "#ffffff", width: "device-width", initialScale: 1 };

export default function RootLayout({ children }: { children: React.ReactNode }) {
  return (
    <html lang="vi">
      <body className="flex min-h-dvh flex-col">
        <a href="#main" className="sr-only focus:not-sr-only focus:fixed focus:left-4 focus:top-3 focus:z-50 focus:rounded-lg focus:bg-fg focus:px-3 focus:py-2 focus:text-sm focus:text-white">Bỏ qua điều hướng</a>
        <SiteHeader />
        <main id="main" className="flex-1">{children}</main>
        <footer className="mt-0 border-t border-line bg-white">
          <div className="container-x flex flex-col gap-6 py-10 text-sm text-muted md:flex-row md:items-start md:justify-between">
            <div className="max-w-md">
              <p className="mono flex items-center gap-2 text-[13px] font-medium text-fg"><span className="inline-block size-2 rounded-[3px] bg-accent" aria-hidden /><span className="uppercase tracking-[0.28em]">vibesec</span></p>
              <p className="mt-3 leading-relaxed">Chỉ thực hiện các kiểm tra thụ động, không phá hoại. Điểm số là đánh giá cấu hình từ bên ngoài, không phải bằng chứng website an toàn tuyệt đối.</p>
            </div>
            <nav aria-label="Liên kết chân trang" className="flex flex-wrap gap-x-6 gap-y-2">
              <Link className="hover:text-fg" href="/demo">Bản demo</Link>
              <Link className="hover:text-fg" href="/#checks">Những gì chúng tôi kiểm tra</Link>
              <Link className="hover:text-fg" href="/phuong-phap">Phương pháp</Link>
            </nav>
          </div>
        </footer>
      </body>
    </html>
  );
}
