import type { Metadata } from "next";
import Link from "next/link";
import { Report } from "@/components/Report";
import { demoReport } from "@/lib/demo";

export const metadata: Metadata = { title: "Báo cáo demo" };

export default function DemoPage() {
  return <Report data={demoReport()} actions={<Link href="/" className="btn-primary btn-sm">Quét website của bạn</Link>} />;
}
