import type { Metadata } from "next";
import Link from "next/link";
import { notFound } from "next/navigation";
import { getAdmin } from "@/lib/auth/admin";
import { getDb } from "@/lib/cf";
import * as repo from "@/lib/db/repo";
import { adminCountNewHelp } from "@/lib/db/help-repo";
import { formatDate, formatDuration, relativeTime } from "@/lib/format";

export const metadata: Metadata = { title: "Quản trị", robots: { index: false } };
export const dynamic = "force-dynamic";

export default async function Admin() {
  if (!(await getAdmin())) notFound(); // không tiết lộ khu vực quản trị cho người khác
  const db = await getDb();
  const [o, users, fb, helpNew] = await Promise.all([repo.adminOverview(db), repo.adminListUsers(db), repo.adminListFeedback(db), adminCountNewHelp(db)]);
  const stats = [
    ["Người dùng", o.users], ["Hoạt động 24 giờ", o.activeToday], ["Lượt quét tổng", o.scansTotal], ["Lượt quét 24 giờ", o.scans24h],
    ["Cuộc chat chưa đọc", o.unreadChats], ["Tổng thời lượng dùng", formatDuration(o.usageSecondsTotal)],
  ] as const;
  return (
    <div className="container-x py-10 sm:py-14">
      <h1 className="reveal text-3xl font-semibold tracking-tight">Quản trị</h1>
      <Link href="/admin/yeu-cau" className="btn-ghost btn-sm mt-3 inline-flex">Yêu cầu nhờ chuyên gia{helpNew > 0 && <span className="chip-accent">{helpNew} mới</span>}</Link>
      <section className="mt-6 grid grid-cols-2 gap-4 md:grid-cols-3 lg:grid-cols-6" aria-label="Tổng quan">
        {stats.map(([k, v], i) => (
          <div key={k} className="panel reveal p-4" style={{ ["--i" as string]: i }}>
            <h2 className="eyebrow">{k}</h2>
            <p className="num mt-2 text-2xl font-semibold">{v}</p>
          </div>
        ))}
      </section>
      <section className="mt-10" aria-label="Người dùng">
        <h2 className="text-lg font-semibold">Người dùng</h2>
        <div className="panel mt-3 overflow-x-auto">
          <table className="w-full min-w-[44rem] text-left text-sm">
            <thead className="eyebrow border-b border-line"><tr><th className="p-3">Người dùng</th><th className="p-3">Lượt quét</th><th className="p-3">Thời lượng dùng</th><th className="p-3">Hoạt động gần nhất</th><th className="p-3">Tham gia</th><th className="p-3">Chat</th></tr></thead>
            <tbody>
              {users.map((u) => (
                <tr key={u.id} className="border-b border-line last:border-0 hover:bg-surface">
                  <td className="p-3"><Link href={`/admin/users/${u.id}`} className="font-medium text-accent hover:underline">{u.display_name ?? u.email}</Link>{u.display_name && <div className="text-xs text-faint">{u.email}</div>}</td>
                  <td className="num p-3">{u.scan_count}</td>
                  <td className="num p-3">{formatDuration(u.usage_seconds)}</td>
                  <td className="p-3 text-muted">{u.last_seen_at ? relativeTime(u.last_seen_at) : "—"}</td>
                  <td className="p-3 text-muted">{formatDate(u.created_at)}</td>
                  <td className="p-3">{u.unread > 0 ? <span className="chip-accent">{u.unread} mới</span> : <span className="text-faint">—</span>}</td>
                </tr>
              ))}
              {users.length === 0 && <tr><td colSpan={6} className="p-6 text-center text-muted">Chưa có người dùng.</td></tr>}
            </tbody>
          </table>
        </div>
      </section>
      <section className="mt-10" aria-label="Phản hồi">
        <h2 className="text-lg font-semibold">Phản hồi sau khi quét <span className="num ml-2 text-sm font-normal text-muted">{fb.total ? `${fb.avg?.toFixed(1)}/5 · ${fb.total} lượt` : "chưa có"}</span></h2>
        <ul className="panel mt-3 divide-y divide-line">
          {fb.rows.map((r) => (
            <li key={r.id} className="p-3 text-sm">
              <div className="flex flex-wrap items-center gap-x-3 gap-y-1"><span aria-label={`${r.rating} trên 5`}>{"★".repeat(r.rating)}<span className="text-line-strong">{"★".repeat(5 - r.rating)}</span></span><span className="mono text-xs text-muted">{r.host}</span><span className="text-xs text-faint">{r.email} · {relativeTime(r.created_at)}</span></div>
              {r.tags && <p className="mt-1 flex flex-wrap gap-1">{r.tags.split(",").map((t) => <span key={t} className="chip-info">{t}</span>)}</p>}
              {r.comment && <p className="mt-1 whitespace-pre-wrap text-muted">{r.comment}</p>}
            </li>
          ))}
          {fb.rows.length === 0 && <li className="p-6 text-center text-muted">Chưa có phản hồi.</li>}
        </ul>
      </section>
    </div>
  );
}
