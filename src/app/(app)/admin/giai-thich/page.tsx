import type { Metadata } from "next";
import Link from "next/link";
import { notFound } from "next/navigation";
import { getAdmin } from "@/lib/auth/admin";
import { getDb } from "@/lib/cf";
import { clarityByRule, clarityLevel, MIN_VOTES, recentUnclearComments, unclearLowerBound } from "@/lib/db/explain-feedback";
import { formatDate } from "@/lib/format";
import { ALL_RULES } from "@/lib/scanner/rules";

export const metadata: Metadata = { title: "Độ rõ của giải thích", robots: { index: false } };
export const dynamic = "force-dynamic";

export default async function ExplainClarityAdmin() {
  if (!(await getAdmin())) notFound();
  const db = await getDb();
  const [rows, comments] = await Promise.all([clarityByRule(db), recentUnclearComments(db)]);
  const title = new Map(ALL_RULES.map((r) => [r.id, r.title]));
  const total = rows.reduce((s, r) => s + r.total, 0), unclear = rows.reduce((s, r) => s + r.unclear, 0);
  return (
    <div className="container-x py-10 sm:py-14">
      <Link href="/admin" className="text-sm text-muted hover:text-fg">← Quản trị</Link>
      <h1 className="mt-2 text-3xl font-semibold tracking-tight">Độ rõ của giải thích</h1>
      <p className="mt-2 max-w-2xl text-sm text-muted">{`Phiếu “Giải thích này có rõ không?” từ người dùng. Chỉ mục có ít nhất ${MIN_VOTES} phiếu và cận dưới (Wilson 95%) của tỉ lệ “Chưa” ≥ 30% mới được đánh dấu ưu tiên; mẫu nhỏ chỉ hiển thị số liệu, không kết luận. Không lưu tên miền, URL hay IP.`}</p>
      <p className="num mt-4 text-sm">{total} phiếu · <span className="text-crit">{unclear} chưa rõ</span> ({total ? Math.round((unclear / total) * 100) : 0}%)</p>

      <div className="panel mt-4 overflow-x-auto">
        <table className="w-full min-w-[40rem] text-left text-sm">
          <thead className="eyebrow border-b border-line"><tr><th className="p-3">Luật</th><th className="p-3">Biến thể</th><th className="p-3">Rõ</th><th className="p-3">Chưa rõ</th><th className="p-3">% chưa rõ</th></tr></thead>
          <tbody>
            {rows.map((r) => {
              const pct = Math.round((r.unclear / r.total) * 100);
              const level = clarityLevel(r.unclear, r.total);
              const lb = Math.round(unclearLowerBound(r.unclear, r.total) * 100);
              return (
                <tr key={`${r.rule_id}|${r.variant}`} className="border-b border-line last:border-0">
                  <td className="p-3"><span className="font-medium">{title.get(r.rule_id) ?? r.rule_id}</span><div className="mono text-xs text-faint">{r.rule_id}</div></td>
                  <td className="mono p-3 text-xs text-muted">{r.variant || "—"}</td>
                  <td className="num p-3">{r.clear}</td>
                  <td className="num p-3">{r.unclear}</td>
                  <td className="p-3">{level === "insufficient"
                    ? <span className="chip-info" title={`Mới ${r.total}/${MIN_VOTES} phiếu — chưa đủ để kết luận`}>{pct}% · mẫu nhỏ (n={r.total})</span>
                    : <span className={level === "priority" ? "chip-crit" : level === "watch" ? "chip-med" : "chip-ok"} title={`Cận dưới 95%: ${lb}%`}>{pct}% · {level === "priority" ? "ưu tiên viết lại" : level === "watch" ? "theo dõi" : "ổn"}</span>}</td>
                </tr>
              );
            })}
            {rows.length === 0 && <tr><td colSpan={5} className="p-6 text-center text-muted">Chưa có phiếu nào.</td></tr>}
          </tbody>
        </table>
      </div>

      <h2 className="mt-10 text-lg font-semibold">Nhận xét gần đây</h2>
      <ul className="panel mt-3 divide-y divide-line">
        {comments.map((c, i) => (
          <li key={i} className="p-3.5 text-sm">
            <p>{c.comment}</p>
            <p className="mono mt-1 text-xs text-faint">{c.rule_id}{c.variant ? ` · ${c.variant}` : ""} · {c.source === "quick" ? "quét miễn phí" : "báo cáo đầy đủ"} · {c.mode === "technical" ? "kỹ thuật" : "dễ hiểu"} · {formatDate(c.updated_at)}</p>
          </li>
        ))}
        {comments.length === 0 && <li className="p-6 text-center text-sm text-muted">Chưa có nhận xét.</li>}
      </ul>
    </div>
  );
}
