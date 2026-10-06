import { PLAIN_TITLES } from "../beginner";
import { CATEGORY_LABEL } from "../i18n";
import type { Finding } from "../scanner/types";
import { bySeverity, item, scoreItems, type ItemScore, type ItemSource, type LaunchVerdict, type ProjectItem } from "./types";

export interface WebsiteSource { scanId: string; host: string; mode: "quick" | "full"; completedAt: string; findings: Finding[] }
export interface ProjectSource { id: string; label: string; createdAt: string; items: ProjectItem[] }
export type Skippable = "code" | "system";

export interface LaunchInput { website: WebsiteSource | null; code: ProjectSource | null; system: ProjectSource | null; skipped: Skippable[] }

export interface LaunchEvaluation {
  items: ProjectItem[];
  verdict: LaunchVerdict;
  /** Lỗi bắt buộc sửa (fail mức nghiêm trọng/cao). */
  blockers: ProjectItem[];
  /** Nên sửa: fail mức trung bình + nguồn chưa quét. */
  shoulds: ProjectItem[];
  score: ItemScore;
  reasons: string[];
}

const SOURCE_NAME: Record<ItemSource, string> = { website: "Website", code: "Mã nguồn", system: "Hệ thống" };
export const SOURCE_LABEL = SOURCE_NAME;
const SCAN_HREF: Record<ItemSource, string> = { website: "/quet-nang-cao", code: "/quet-ma-nguon", system: "/quet-he-thong" };

/** Chuyển kết quả quét website hiện có thành mục kiểm tra (không chạy lại gì cả). */
export function websiteItems(w: WebsiteSource): ProjectItem[] {
  const out: ProjectItem[] = [];
  for (const f of w.findings) {
    if (f.status !== "fail" && f.status !== "pass") continue;
    const r = f.remediation;
    out.push(item({
      id: f.ruleId, fingerprint: f.fingerprint, group: CATEGORY_LABEL[f.category] ?? f.category, source: "website", title: PLAIN_TITLES[f.ruleId] ?? f.title, severity: f.severity, confidence: f.confidence,
      status: f.status, summary: f.summary, why: f.explanation, evidence: f.evidence.slice(0, 5), technical: f.technical,
      fix: f.status === "fail" && r?.summary ? { summary: r.summary, steps: r.steps, snippet: r.snippets[0] ? { label: r.snippets[0].label, language: r.snippets[0].language, code: r.snippets[0].code } : undefined } : undefined,
    }));
  }
  return out;
}

const missing = (source: Skippable | "website", why: string): ProjectItem => item({
  id: `missing-${source}`, group: SOURCE_NAME[source], source, title: `${SOURCE_NAME[source]} chưa được quét`, severity: "medium", status: "unknown",
  summary: why, why: "Chưa quét thì chưa biết có lỗi hay không. Một lỗi nghiêm trọng ở phần này có thể nằm ngay trước ngày ra mắt.",
  action: { label: `Quét ${SOURCE_NAME[source].toLowerCase()}`, href: SCAN_HREF[source] },
});

export function evaluateLaunch(inp: LaunchInput): LaunchEvaluation {
  const items: ProjectItem[] = [];
  if (inp.website) {
    items.push(...websiteItems(inp.website));
    if (inp.website.mode === "quick") items.push(item({ id: "website-quick", group: "Website", source: "website", title: "Website mới được quét cơ bản", severity: "medium", status: "unknown", summary: "Quét cơ bản bỏ qua việc đọc mã JavaScript nên chưa thấy khoá bí mật hay thư viện lỗi thời trong trang.", why: "Khoá bí mật lộ trong JavaScript là lỗi phổ biến nhất của website làm nhanh.", action: { label: "Quét nâng cao", href: `${SCAN_HREF.website}?scan=${encodeURIComponent(inp.website.host)}` } }));
  } else items.push(missing("website", "Chưa có lượt quét website nào được chọn. Hãy quét website trước khi đánh giá."));
  for (const s of ["code", "system"] as const) {
    if (inp.skipped.includes(s)) continue; // người dùng báo không áp dụng
    const src = inp[s];
    if (src) items.push(...src.items.filter((i) => i.status !== "info").map((i) => ({ ...i, source: s })));
    else items.push(missing(s, s === "code" ? "Chưa quét mã nguồn. Khoá bí mật nằm trong code là lý do hàng đầu khiến dự án bị tấn công." : "Chưa quét hệ thống (database, storage, đăng nhập). Database mở công khai là lỗi hay gặp nhất ở dự án Supabase/Firebase."));
  }

  const blockers = items.filter((i) => i.status === "fail" && (i.severity === "critical" || i.severity === "high")).sort(bySeverity);
  const shoulds = items.filter((i) => (i.status === "fail" && i.severity === "medium") || (i.status === "unknown" && (i.id.startsWith("missing-") || i.id === "website-quick"))).sort(bySeverity);
  const verdict: LaunchVerdict = blockers.length ? "not_ready" : shoulds.length ? "fix_first" : "ready";
  const reasons: string[] = [];
  if (blockers.length) reasons.push(`${blockers.length} lỗi bắt buộc sửa trước khi ra mắt.`);
  const fails = shoulds.filter((s) => s.status === "fail").length;
  if (fails) reasons.push(`${fails} vấn đề mức trung bình nên sửa.`);
  const un = shoulds.filter((s) => s.status === "unknown");
  if (un.length) reasons.push(`${un.length} phần chưa được kiểm tra đầy đủ.`);
  if (verdict === "ready") reasons.push("Không còn lỗi nghiêm trọng hay trung bình trong những phần đã quét.");
  return { items, verdict, blockers, shoulds, score: scoreItems(items), reasons };
}

// ------------------------------------------------------------------ Before / After

export interface LaunchDiff {
  previousAt: string;
  previousVerdict: LaunchVerdict | null;
  previousScore: number | null;
  scoreDelta: number | null;
  resolved: ProjectItem[];
  added: ProjectItem[];
  remaining: ProjectItem[];
  /** Nguồn có lỗi ở lần trước nhưng lần này không được kiểm tra: không tính là đã sửa. */
  notRechecked: ProjectItem[];
}

/** So sánh theo fingerprint các mục LỖI. Chỉ coi là "đã sửa" khi nguồn đó vẫn được kiểm tra ở lần này. */
export function compareLaunch(prev: { items: ProjectItem[]; createdAt: string; verdict: LaunchVerdict | null; score: number | null }, now: LaunchEvaluation): LaunchDiff {
  const checked = (src?: ItemSource) => now.items.some((i) => i.source === src && (i.status === "pass" || i.status === "fail"));
  const nowFail = new Map(now.items.filter((i) => i.status === "fail").map((i) => [i.fingerprint, i]));
  const prevFail = prev.items.filter((i) => i.status === "fail");
  const resolved: ProjectItem[] = [], remaining: ProjectItem[] = [], notRechecked: ProjectItem[] = [];
  for (const p of prevFail) {
    if (nowFail.has(p.fingerprint)) remaining.push(nowFail.get(p.fingerprint)!);
    else if (checked(p.source)) resolved.push(p);
    else notRechecked.push(p);
  }
  const prevKeys = new Set(prevFail.map((i) => i.fingerprint));
  const added = [...nowFail.values()].filter((i) => !prevKeys.has(i.fingerprint));
  return { previousAt: prev.createdAt, previousVerdict: prev.verdict, previousScore: prev.score, scoreDelta: prev.score === null ? null : now.score.score - prev.score, resolved: resolved.sort(bySeverity), added: added.sort(bySeverity), remaining: remaining.sort(bySeverity), notRechecked };
}
