import type { Metadata } from "next";
import Link from "next/link";
import { Report } from "@/components/Report";
import { demoReport } from "@/lib/demo";

export const metadata: Metadata = { title: "Demo report" };

export default function DemoPage() {
  return (
    <Report
      data={demoReport()}
      actions={<Link href="/" className="h-9 px-4 inline-flex items-center rounded-md bg-fg text-bg text-sm font-medium hover:bg-white">Scan your own site</Link>}
    />
  );
}
