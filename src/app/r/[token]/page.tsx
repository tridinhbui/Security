import type { Metadata } from "next";
import Link from "next/link";
import { notFound } from "next/navigation";
import { Report } from "@/components/Report";
import { hashToken } from "@/lib/crypto";
import { toReportData } from "@/lib/report-data";
import { loadSharedReport } from "@/lib/reports";
import * as repo from "@/lib/db/repo";
import { getDb } from "@/lib/cf";

export const metadata: Metadata = { title: "Báo cáo được chia sẻ", robots: { index: false, follow: false }, referrer: "no-referrer" };
export const dynamic = "force-dynamic";

export default async function SharedReport({ params }: { params: Promise<{ token: string }> }) {
  const { token } = await params;
  if (!/^[A-Za-z0-9_-]{43}$/.test(token)) notFound(); // 32 random bytes, base64url
  const db = await getDb();
  const share = await repo.getShareByHash(db, await hashToken(token));
  if (!share || share.revoked_at || (share.expires_at && new Date(share.expires_at) < new Date())) notFound();

  const view = await loadSharedReport(db, share.scan_id); // raw headers stay private to the owner
  if (!view || view.scan.status !== "completed") notFound();
  return (
    <Report
      data={toReportData(view, { variant: "shared" })}
      actions={<Link href="/" className="h-9 px-4 inline-flex items-center rounded-md bg-fg text-bg text-sm font-medium hover:bg-white">Quét website của bạn</Link>}
    />
  );
}
