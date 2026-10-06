import type { Metadata } from "next";
import Link from "next/link";
import { notFound } from "next/navigation";
import { ChatBox } from "@/components/ChatBox";
import { getAdmin } from "@/lib/auth/admin";
import { getDb } from "@/lib/cf";
import * as repo from "@/lib/db/repo";
import { formatDate, formatDuration, relativeTime } from "@/lib/format";
import { UUID } from "@/lib/http/guards";

export const metadata: Metadata = { title: "Chi tiết người dùng", robots: { index: false } };
export const dynamic = "force-dynamic";

export default async function AdminUser({ params }: { params: Promise<{ id: string }> }) {
  const { id } = await params;
  if (!(await getAdmin()) || !UUID.test(id)) notFound();
  const db = await getDb();
  const [u, scans] = await Promise.all([repo.adminGetUser(db, id), repo.adminUserScans(db, id)]);
  if (!u) notFound();
  return (
    <div className="container-x py-10 sm:py-14">
      <Link href="/admin" className="text-sm text-muted hover:text-fg">← Quản trị</Link>
      <h1 className="mt-2 text-3xl font-semibold tracking-tight">{u.display_name ?? u.email}</h1>
      <p className="mono mt-1 text-sm text-faint">{u.email} · tham gia {formatDate(u.created_at)} · dùng {formatDuration(u.usage_seconds)} · hoạt động {u.last_seen_at ? relativeTime(u.last_seen_at) : "—"}</p>
      <div className="mt-8 grid gap-8 lg:grid-cols-2">
        <section aria-label="Các trang đã quét">
          <h2 className="text-lg font-semibold">Trang đã quét ({scans.length})</h2>
          <div className="panel mt-3 divide-y divide-line overflow-hidden">
            {scans.map((s) => (
              <div key={s.id} className="flex items-center justify-between gap-3 p-3 text-sm">
                <div className="min-w-0"><p className="truncate font-medium">{s.normalized_url}</p><p className="text-xs text-faint">{formatDate(s.created_at)}</p></div>
                <span className="mono shrink-0 text-xs text-muted">{s.status === "completed" ? `${s.score}/${s.grade}` : s.status}</span>
              </div>
            ))}
            {scans.length === 0 && <p className="p-6 text-center text-sm text-muted">Chưa quét trang nào.</p>}
          </div>
        </section>
        <section aria-label="Chat với người dùng">
          <h2 className="mb-3 text-lg font-semibold">Chat trực tiếp</h2>
          <ChatBox endpoint={`/api/admin/chat/${u.id}`} me="admin" placeholder="Trả lời người dùng…" />
        </section>
      </div>
    </div>
  );
}
