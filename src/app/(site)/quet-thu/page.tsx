import type { Metadata } from "next";
import { QuickScanRunner } from "@/components/QuickScanRunner";
import { ScanForm } from "@/components/ScanForm";
import { getUser } from "@/lib/auth/next";
import { ALL_RULES } from "@/lib/scanner/rules";

export const metadata: Metadata = { title: "Quét thử miễn phí", robots: { index: false } };
export const dynamic = "force-dynamic";

export default async function QuickScanPage({ searchParams }: { searchParams: Promise<{ url?: string }> }) {
  const { url } = await searchParams;
  const target = (url ?? "").trim().slice(0, 2048);
  const user = await getUser();
  return (
    <div className="container-x max-w-3xl py-10 sm:py-14">
      <p className="eyebrow reveal">quét thử miễn phí</p>
      <h1 className="reveal mt-2 text-3xl font-semibold tracking-tight sm:text-4xl">Kiểm tra nhanh website của bạn</h1>
      <p className="mt-3 text-[15px] text-muted">Không cần tài khoản. Chỉ xem những gì ai cũng thấy được, không thay đổi website.</p>
      <div className="mt-6"><ScanForm authed={false} initialUrl={target} label="Quét miễn phí" size="md" /></div>
      <p className="mt-3 text-[13px] text-faint">Quét thụ động · Không đăng nhập · Không thay đổi website</p>
      {target ? <QuickScanRunner key={target} url={target} authed={!!user} ruleCount={ALL_RULES.length} /> : null}
    </div>
  );
}
