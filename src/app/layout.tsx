import type { Metadata, Viewport } from "next";
import Link from "next/link";
import "./globals.css";
import { SiteHeader } from "@/components/SiteHeader";

export const metadata: Metadata = {
  title: { default: "VibeSec — kiểm tra bảo mật website bằng ngôn ngữ dễ hiểu", template: "%s · VibeSec" },
  description: "Dán một URL để nhận báo cáo bảo mật rõ ràng, dễ hiểu cho người mới. Chỉ kiểm tra thụ động, không phá hoại, kèm cách khắc phục cụ thể.",
  robots: { index: true, follow: true },
};
export const viewport: Viewport = { themeColor: "#0a0b0d", width: "device-width", initialScale: 1 };

export default function RootLayout({ children }: { children: React.ReactNode }) {
  return (
    <html lang="vi">
      <body className="min-h-dvh flex flex-col">
        <SiteHeader />
        <main className="flex-1">{children}</main>
        <footer className="border-t border-line mt-24">
          <div className="mx-auto max-w-5xl px-5 py-8 text-sm text-muted flex flex-col sm:flex-row gap-3 sm:items-center sm:justify-between">
            <p>VibeSec chỉ thực hiện các kiểm tra thụ động, không phá hoại. Điểm số là đánh giá cấu hình từ bên ngoài, không phải bằng chứng cho thấy website an toàn tuyệt đối.</p>
            <nav className="flex gap-5 shrink-0">
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
