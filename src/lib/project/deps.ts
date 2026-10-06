import type { Severity } from "../scanner/types";
import type { SourceFile } from "./github";
import { item, type ProjectItem } from "./types";

const G_DEPS = "Thư viện (dependencies)";

export interface Dep { name: string; version: string; eco: "npm" | "PyPI"; direct: boolean; manifest: string }
export interface ParsedDeps { deps: Dep[]; manifests: string[]; hasLockfile: boolean; truncated: boolean; directNpm: { name: string; version: string; manifest: string }[] }

const MAX_DEPS = 1500;
const dirOf = (p: string) => (p.includes("/") ? p.slice(0, p.lastIndexOf("/")) : "");
const cleanVer = (v: string) => (v.match(/\d+(?:\.\d+){0,2}(?:-[\w.]+)?/)?.[0] ?? "");

function tryJson<T>(s: string): T | null { try { return JSON.parse(s) as T; } catch { return null; } }

interface LockV1 { dependencies?: Record<string, { version?: string; dev?: boolean; dependencies?: LockV1["dependencies"] }> }
function walkV1(d: LockV1["dependencies"], out: Map<string, string>) {
  for (const [name, v] of Object.entries(d ?? {})) {
    if (v.version && !v.dev && /^\d/.test(v.version)) out.set(`${name}@${v.version}`, v.version);
    walkV1(v.dependencies, out);
  }
}

/** Đọc danh sách thư viện đang dùng từ lockfile (chính xác nhất) hoặc package.json / requirements.txt. */
export function parseManifests(files: SourceFile[]): ParsedDeps {
  const byPath = new Map(files.map((f) => [f.path, f.content]));
  const seen = new Map<string, Dep>();
  const manifests: string[] = [];
  const directNpm: ParsedDeps["directNpm"] = [];
  let hasLockfile = false;
  const add = (d: Dep) => { const k = `${d.eco}:${d.name}@${d.version}`; const prev = seen.get(k); if (!prev) seen.set(k, d); else if (d.direct) prev.direct = true; };

  for (const f of files) {
    if (/(?:^|\/)node_modules\//.test(f.path)) continue;
    if (f.path.split("/").length > 4) continue;
    if (/(?:^|\/)package\.json$/.test(f.path)) {
      const pj = tryJson<{ dependencies?: Record<string, string>; name?: string }>(f.content);
      if (!pj) continue;
      manifests.push(f.path);
      const dir = dirOf(f.path);
      const sib = (n: string) => byPath.get(dir ? `${dir}/${n}` : n);
      const direct = pj.dependencies ?? {};
      const resolved = new Map<string, string>(); // name → phiên bản thật theo lockfile (ưu tiên bản cấp cao nhất)
      const lock = sib("package-lock.json");
      const yarn = sib("yarn.lock");
      if (lock) {
        const l = tryJson<{ packages?: Record<string, { version?: string; dev?: boolean; link?: boolean }> } & LockV1>(lock);
        if (l) {
          hasLockfile = true;
          if (l.packages) {
            for (const [key, v] of Object.entries(l.packages)) {
              if (!key || v.dev || v.link || !v.version) continue;
              const name = key.slice(key.lastIndexOf("node_modules/") + "node_modules/".length);
              if (!resolved.has(name) || key === `node_modules/${name}`) resolved.set(name, v.version);
              add({ name, version: v.version, eco: "npm", direct: name in direct, manifest: f.path });
            }
          } else { const m = new Map<string, string>(); walkV1(l.dependencies, m); for (const [k, v] of m) { const name = k.slice(0, k.lastIndexOf("@")); resolved.set(name, v); add({ name, version: v, eco: "npm", direct: name in direct, manifest: f.path }); } }
        }
      } else if (yarn) {
        hasLockfile = true;
        for (const m of yarn.matchAll(/^"?(@?[^@\s"]+)@[^\n]*:\n(?:[ \t]+[^\n]*\n)*?[ \t]+version "([^"]+)"/gm)) {
          resolved.set(m[1]!, m[2]!);
          add({ name: m[1]!, version: m[2]!, eco: "npm", direct: m[1]! in direct, manifest: f.path });
        }
      }
      for (const [name, range] of Object.entries(direct)) {
        const ver = resolved.get(name) ?? cleanVer(range);
        if (!ver || /^(?:git|http|file|link|workspace|npm):/.test(range)) continue;
        directNpm.push({ name, version: ver, manifest: f.path });
        if (!resolved.size) add({ name, version: ver, eco: "npm", direct: true, manifest: f.path });
      }
    } else if (/(?:^|\/)requirements[\w.-]*\.txt$/.test(f.path)) {
      manifests.push(f.path);
      for (const line of f.content.split("\n")) {
        const m = line.trim().match(/^([A-Za-z0-9_.-]+)(?:\[[^\]]*\])?\s*==\s*([\w.]+)/);
        if (m) add({ name: m[1]!.toLowerCase(), version: m[2]!, eco: "PyPI", direct: true, manifest: f.path });
      }
    }
  }
  const all = [...seen.values()];
  return { deps: all.slice(0, MAX_DEPS), manifests, hasLockfile, truncated: all.length > MAX_DEPS, directNpm };
}

// ------------------------------------------------------------------ so sánh phiên bản

export const cmpVer = (a: string, b: string): number => {
  const pa = a.split(/[.-]/).map((x) => parseInt(x, 10) || 0), pb = b.split(/[.-]/).map((x) => parseInt(x, 10) || 0);
  for (let i = 0; i < Math.max(pa.length, pb.length, 3); i++) { const d = (pa[i] ?? 0) - (pb[i] ?? 0); if (d) return d; }
  return 0;
};
const major = (v: string) => parseInt(v.split(".")[0]!, 10) || 0;

// ------------------------------------------------------------------ OSV (CVE)

interface OsvVuln { id: string; summary?: string; aliases?: string[]; database_specific?: { severity?: string }; affected?: { package?: { name?: string; ecosystem?: string }; ranges?: { events?: { introduced?: string; fixed?: string }[] }[] }[] }
export interface VulnHit { dep: Dep; id: string; cve: string | null; severity: Severity; summary: string; fixed: string | null; detailed: boolean }

const OSV_SEV: Record<string, Severity> = { CRITICAL: "critical", HIGH: "high", MODERATE: "medium", MEDIUM: "medium", LOW: "low" };
const timeout = () => AbortSignal.timeout(9_000);

async function pool<T, R>(arr: T[], n: number, fn: (x: T) => Promise<R>): Promise<R[]> {
  const out: R[] = [];
  let i = 0;
  await Promise.all(Array.from({ length: Math.min(n, arr.length) }, async () => { while (i < arr.length) { const k = i++; out[k] = await fn(arr[k]!); } }));
  return out;
}

export async function findVulns(deps: Dep[], fetcher: typeof fetch = fetch): Promise<{ hits: VulnHit[]; ok: boolean }> {
  if (!deps.length) return { hits: [], ok: true };
  const ids = new Map<string, Set<number>>(); // vuln id → chỉ số dep
  try {
    for (let start = 0; start < deps.length; start += 500) {
      const chunk = deps.slice(start, start + 500);
      const res = await fetcher("https://api.osv.dev/v1/querybatch", {
        method: "POST", headers: { "content-type": "application/json" }, signal: timeout(),
        body: JSON.stringify({ queries: chunk.map((d) => ({ package: { name: d.name, ecosystem: d.eco }, version: d.version })) }),
      });
      if (!res.ok) return { hits: [], ok: false };
      const data = (await res.json()) as { results?: { vulns?: { id: string }[] }[] };
      (data.results ?? []).forEach((r, i) => { for (const v of r.vulns ?? []) { const s = ids.get(v.id) ?? new Set(); s.add(start + i); ids.set(v.id, s); } });
    }
  } catch { return { hits: [], ok: false }; }

  // Lấy chi tiết (mức độ, bản vá) cho tối đa 40 lỗ hổng, ưu tiên thư viện trực tiếp.
  const order = [...ids.entries()].sort((a, b) => Number(deps[[...b[1]][0]!]!.direct) - Number(deps[[...a[1]][0]!]!.direct));
  const detail = new Map<string, OsvVuln>();
  await pool(order.slice(0, 40), 8, async ([id]) => {
    try { const r = await fetcher(`https://api.osv.dev/v1/vulns/${encodeURIComponent(id)}`, { signal: timeout() }); if (r.ok) detail.set(id, (await r.json()) as OsvVuln); } catch { /* bỏ qua chi tiết */ }
  });

  const hits: VulnHit[] = [];
  for (const [id, idxs] of ids) {
    const v = detail.get(id);
    for (const i of idxs) {
      const dep = deps[i]!;
      let fixed: string | null = null;
      for (const a of v?.affected ?? []) {
        if (a.package?.name?.toLowerCase() !== dep.name.toLowerCase()) continue;
        const fx = (a.ranges ?? []).flatMap((r) => (r.events ?? []).map((e) => e.fixed)).filter((x): x is string => !!x && cmpVer(x, dep.version) > 0);
        const same = fx.filter((x) => major(x) === major(dep.version)).sort(cmpVer)[0];
        fixed = same ?? fx.sort(cmpVer)[0] ?? fixed;
      }
      hits.push({ dep, id, cve: v?.aliases?.find((a) => a.startsWith("CVE-")) ?? null, severity: OSV_SEV[(v?.database_specific?.severity ?? "").toUpperCase()] ?? "medium", summary: v?.summary ?? "Chưa lấy được mô tả chi tiết.", fixed, detailed: !!v });
    }
  }
  return { hits, ok: true };
}

export function vulnItems(hits: VulnHit[], parsed: ParsedDeps, queried: boolean): ProjectItem[] {
  if (!queried) return [item({ id: "deps-cve-unknown", group: G_DEPS, source: "code", title: "Chưa kiểm tra được lỗ hổng của thư viện", severity: "info", status: "unknown", summary: "Dịch vụ cơ sở dữ liệu lỗ hổng (OSV.dev) không phản hồi lúc này. Hãy quét lại sau.", why: "Thư viện cũ có lỗ hổng đã công bố là lối vào phổ biến của kẻ tấn công." })];
  if (!hits.length) return [item({ id: "deps-cve-clean", group: G_DEPS, source: "code", title: "Thư viện không có lỗ hổng đã công bố", severity: "info", status: "pass", summary: `Đã đối chiếu ${parsed.deps.length} thư viện với cơ sở dữ liệu OSV.dev, không thấy lỗ hổng nào.${parsed.hasLockfile ? "" : " (Dựa trên phiên bản khai báo vì kho chưa có lockfile.)"}`, why: "Thư viện cũ có lỗ hổng đã công bố là lối vào phổ biến của kẻ tấn công." })];

  const byDep = new Map<string, VulnHit[]>();
  for (const h of hits) { const k = `${h.dep.eco}:${h.dep.name}@${h.dep.version}`; byDep.set(k, [...(byDep.get(k) ?? []), h]); }
  const rank: Record<Severity, number> = { critical: 0, high: 1, medium: 2, low: 3, info: 4 };
  const groups = [...byDep.values()].sort((a, b) => Math.min(...a.map((h) => rank[h.severity])) - Math.min(...b.map((h) => rank[h.severity])) || Number(b[0]!.dep.direct) - Number(a[0]!.dep.direct));
  const out: ProjectItem[] = [];
  for (const g of groups.slice(0, 12)) {
    const d = g[0]!.dep;
    const sev = g.map((h) => h.severity).sort((a, b) => rank[a] - rank[b])[0]!;
    const fixes = [...new Set(g.map((h) => h.fixed).filter((x): x is string => !!x))].sort(cmpVer);
    const target = fixes.at(-1) ?? null;
    const cmd = d.eco === "npm" ? (d.direct && target ? `npm install ${d.name}@${target}` : "npm audit fix") : `pip install -U ${d.name}${target ? `==${target}` : ""}`;
    out.push(item({
      id: `dep-vuln:${d.name}`, fingerprint: `dep-vuln:${d.eco}:${d.name}@${d.version}`, group: G_DEPS, source: "code", title: `${d.name} ${d.version} có lỗ hổng đã biết`, severity: sev, confidence: g.every((h) => h.detailed) ? "high" : "medium", status: "fail",
      summary: `${g.length} lỗ hổng đã được công bố cho ${d.name} ${d.version}${d.direct ? "" : " (thư viện gián tiếp, do thư viện khác kéo vào)"}.${target ? ` Có bản vá từ ${target}.` : " Chưa thấy thông tin bản vá."}`,
      why: "Lỗ hổng đã công bố được kẻ tấn công dò quét hàng loạt. Dùng bản cũ nghĩa là bạn dễ bị khai thác bằng công cụ có sẵn.",
      fix: { summary: target ? `Nâng ${d.name} lên ${target} hoặc mới hơn.` : `Cập nhật ${d.name} lên bản mới nhất còn được hỗ trợ.`, steps: [d.direct ? "Chạy lệnh bên dưới trong thư mục dự án." : "Đây là thư viện gián tiếp: thử npm audit fix, hoặc nâng thư viện cha đang kéo nó vào.", "Chạy lại test/build để chắc không có gì hỏng.", "Commit lockfile mới."], snippet: { label: "Lệnh cập nhật", language: "bash", code: cmd } },
      evidence: g.slice(0, 5).map((h) => `${h.cve ?? h.id} (${h.severity}) — ${h.summary.slice(0, 90)}`), technical: `Nguồn: OSV.dev · ${d.manifest}`,
    }));
  }
  if (groups.length > 12) out.push(item({ id: "dep-vuln:more", group: G_DEPS, source: "code", title: `Và ${groups.length - 12} thư viện khác có lỗ hổng`, severity: "medium", status: "fail", summary: "Chạy npm audit (hoặc pip-audit) trong dự án để xem đầy đủ danh sách.", why: "Danh sách quá dài nên chỉ hiển thị 12 thư viện nặng nhất.", fix: { summary: "Chạy công cụ kiểm tra có sẵn.", snippet: { label: "Xem toàn bộ", language: "bash", code: "npm audit" } }, evidence: [] }));
  return out;
}

// ------------------------------------------------------------------ gói lỗi thời (npm registry)

export interface OutdatedDep { name: string; current: string; latest: string; majorsBehind: number }

export async function findOutdated(parsed: ParsedDeps, fetcher: typeof fetch = fetch): Promise<{ list: OutdatedDep[]; checked: number }> {
  const direct = parsed.directNpm.slice(0, 30);
  const res = await pool(direct, 8, async (d) => {
    try {
      const r = await fetcher(`https://registry.npmjs.org/${d.name.replace("/", "%2F")}/latest`, { signal: timeout(), headers: { Accept: "application/json" } });
      if (!r.ok) return null;
      const latest = ((await r.json()) as { version?: string }).version;
      return latest ? { name: d.name, current: d.version, latest, majorsBehind: major(latest) - major(d.version) } : null;
    } catch { return null; }
  });
  const ok = res.filter((x): x is OutdatedDep => !!x);
  return { list: ok.filter((x) => x.majorsBehind >= 1).sort((a, b) => b.majorsBehind - a.majorsBehind), checked: ok.length };
}

export function outdatedItem(o: { list: OutdatedDep[]; checked: number }, parsed: ParsedDeps): ProjectItem | null {
  if (!parsed.directNpm.length) return null;
  if (o.checked === 0) return item({ id: "deps-outdated", group: G_DEPS, source: "code", title: "Chưa kiểm tra được thư viện lỗi thời", severity: "info", status: "unknown", summary: "Không truy cập được registry npm lúc này.", why: "Thư viện quá cũ thường không còn được vá lỗi bảo mật." });
  if (!o.list.length) return item({ id: "deps-outdated", group: G_DEPS, source: "code", title: "Thư viện chính đều còn mới", severity: "info", status: "pass", summary: `Đã so sánh ${o.checked} thư viện chính với bản mới nhất: không cái nào lạc hậu từ một phiên bản lớn trở lên.`, why: "Thư viện quá cũ thường không còn được vá lỗi bảo mật." });
  const far = o.list.some((x) => x.majorsBehind >= 2);
  return item({
    id: "deps-outdated", group: G_DEPS, source: "code", title: "Có thư viện đã lỗi thời", severity: far ? "low" : "info", status: far ? "fail" : "info", confidence: "medium",
    summary: `${o.list.length} trong ${o.checked} thư viện chính đang chậm ít nhất một phiên bản lớn so với bản mới nhất.`, why: "Thư viện lạc hậu thường không còn được vá lỗi bảo mật, và càng để lâu việc nâng cấp càng khó.",
    fix: { summary: "Nâng cấp dần, ưu tiên các thư viện chậm nhiều bản nhất; đọc ghi chú phát hành trước khi nâng bản lớn.", snippet: { label: "Xem thư viện cũ", language: "bash", code: "npm outdated" } },
    evidence: o.list.slice(0, 10).map((x) => `${x.name}: ${x.current} → ${x.latest}`),
  });
}

export function lockfileItem(parsed: ParsedDeps): ProjectItem | null {
  if (!parsed.manifests.some((m) => m.endsWith("package.json"))) return null;
  return parsed.hasLockfile
    ? item({ id: "deps-lockfile", group: G_DEPS, source: "code", title: "Có lockfile ghim phiên bản thư viện", severity: "info", status: "pass", summary: "Kho có package-lock.json hoặc yarn.lock.", why: "Lockfile đảm bảo mọi máy cài đúng phiên bản đã kiểm tra." })
    : item({ id: "deps-lockfile", group: G_DEPS, source: "code", title: "Chưa có lockfile", severity: "low", status: "fail", summary: "Không thấy package-lock.json hay yarn.lock, nên không biết chính xác bạn đang dùng phiên bản nào.", why: "Mỗi lần cài có thể kéo về phiên bản khác nhau, kể cả bản có lỗ hổng hoặc bị cài mã độc.", fix: { summary: "Tạo và commit lockfile.", snippet: { label: "Tạo lockfile", language: "bash", code: "npm install\ngit add package-lock.json" } } });
}
