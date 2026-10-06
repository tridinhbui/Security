import type { Metadata } from "next";
import { notFound, redirect } from "next/navigation";
import { LaunchReport, type LaunchSourceInfo } from "@/components/LaunchReport";
import { getUser } from "@/lib/auth/next";
import { getDb } from "@/lib/cf";
import { getProjectScan } from "@/lib/db/project-repo";
import { UUID } from "@/lib/http/guards";
import { compareLaunch, type LaunchEvaluation } from "@/lib/project/launch";
import { bySeverity, scoreItems } from "@/lib/project/types";

export const metadata: Metadata = { title: "Sẵn sàng ra mắt", robots: { index: false } };
export const dynamic = "force-dynamic";

type Meta = { websiteHost?: string | null; websiteAt?: string | null; codeLabel?: string | null; codeAt?: string | null; systemLabel?: string | null; systemAt?: string | null; skipped?: string[]; previousId?: string | null; reasons?: string[] };

export default async function Page({ params, searchParams }: { params: Promise<{ id: string }>; searchParams: Promise<{ vs?: string }> }) {
  const { id } = await params;
  const { vs } = await searchParams;
  if (!UUID.test(id)) notFound();
  const user = await getUser();
  if (!user) redirect(`/login?next=/truoc-ra-mat/${id}`);
  const db = await getDb();
  const s = await getProjectScan(db, user.id, id);
  if (!s || s.kind !== "launch" || !s.verdict) notFound();
  const m = s.meta as Meta;

  const blockers = s.items.filter((i) => i.status === "fail" && (i.severity === "critical" || i.severity === "high")).sort(bySeverity);
  const shoulds = s.items.filter((i) => (i.status === "fail" && i.severity === "medium") || (i.status === "unknown" && (i.id.startsWith("missing-") || i.id === "website-quick"))).sort(bySeverity);
  const prevId = UUID.test(vs ?? "") ? vs! : m.previousId ?? null;
  const prev = prevId ? await getProjectScan(db, user.id, prevId) : null;
  const ev: LaunchEvaluation = { items: s.items, verdict: s.verdict, blockers, shoulds, score: scoreItems(s.items), reasons: m.reasons ?? [] };
  const diff = prev && prev.kind === "launch" ? compareLaunch({ items: prev.items, createdAt: prev.created_at, verdict: prev.verdict, score: prev.score }, ev) : null;

  const src = (key: LaunchSourceInfo["key"], label: string | null | undefined, at: string | null | undefined, href: string): LaunchSourceInfo => {
    const skipped = (m.skipped ?? []).includes(key);
    return { key, state: skipped ? "skipped" : label ? "scanned" : "missing", label: label ?? null, at: at ?? null, rescanHref: href };
  };
  const sources = [
    src("website", m.websiteHost, m.websiteAt, `/quet-nang-cao${m.websiteHost ? `?scan=${encodeURIComponent(m.websiteHost)}` : ""}`),
    src("code", m.codeLabel, m.codeAt, `/quet-ma-nguon${m.codeLabel ? `?repo=${encodeURIComponent(m.codeLabel)}` : ""}`),
    src("system", m.systemLabel, m.systemAt, `/quet-he-thong${m.systemLabel ? `?ref=${encodeURIComponent(m.systemLabel)}` : ""}`),
  ];
  return <LaunchReport data={{ id: s.id, label: s.label, createdAt: s.created_at, verdict: s.verdict, score: s.score ?? 0, grade: s.grade ?? "F", items: s.items, blockers, shoulds, reasons: ev.reasons, sources, diff, previousId: prevId }} />;
}
