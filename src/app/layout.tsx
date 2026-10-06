import type { Metadata, Viewport } from "next";
import "./globals.css";
import { MatMat } from "@/components/matmat/MatMat";
import { MatMatProvider } from "@/components/matmat/MatMatProvider";
import { getUser } from "@/lib/auth/next";

export const metadata: Metadata = {
  title: { default: "VibeSec — kiểm tra bảo mật website bằng ngôn ngữ dễ hiểu", template: "%s · VibeSec" },
  description: "Dán một URL để nhận báo cáo bảo mật rõ ràng, dễ hiểu. Chỉ kiểm tra thụ động, không phá hoại, kèm cách khắc phục cụ thể.",
  robots: { index: true, follow: true },
};
export const viewport: Viewport = { themeColor: "#ffffff", width: "device-width", initialScale: 1 };

export default async function RootLayout({ children }: { children: React.ReactNode }) {
  const user = await getUser();
  return (
    <html lang="vi">
      <body>
        <a href="#main" className="sr-only focus:not-sr-only focus:fixed focus:left-4 focus:top-3 focus:z-50 focus:rounded-lg focus:bg-fg focus:px-3 focus:py-2 focus:text-sm focus:text-white">Bỏ qua điều hướng</a>
        <MatMatProvider>
        {children}
        <MatMat authed={!!user} />
        </MatMatProvider>
      </body>
    </html>
  );
}
