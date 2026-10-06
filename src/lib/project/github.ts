import { untar } from "./tar";

export interface SourceFile { path: string; content: string }
export interface RepoSnapshot { owner: string; repo: string; files: SourceFile[]; allPaths: string[]; truncated: boolean; entries: number; skippedLarge: number }

export class RepoError extends Error {
  constructor(readonly code: "invalid_repo" | "invalid_token" | "not_found" | "auth" | "rate_limit" | "too_big" | "network" | "empty", message: string) { super(message); }
}

const OWNER = /^[A-Za-z0-9](?:[A-Za-z0-9-]{0,38})$/;
const REPO = /^[A-Za-z0-9._-]{1,100}$/;

/** Chấp nhận "owner/repo", "github.com/owner/repo", "https://github.com/owner/repo(.git)(/tree/…)". */
export function parseRepoInput(input: string): { owner: string; repo: string } | null {
  let s = input.trim().replace(/^git@github\.com:/i, "").replace(/^https?:\/\//i, "").replace(/^www\./i, "").replace(/^github\.com\//i, "");
  s = s.split(/[?#]/)[0]!.replace(/\/+$/, "");
  const [owner, repoRaw] = s.split("/");
  const repo = repoRaw?.replace(/\.git$/i, "");
  if (!owner || !repo || !OWNER.test(owner) || !REPO.test(repo) || repo === "." || repo === "..") return null;
  return { owner, repo };
}

export const TOKEN_RE = /^[A-Za-z0-9_-]{20,255}$/;

const TEXT_EXT = /\.(?:[cm]?[jt]sx?|json|ya?ml|toml|ini|cfg|conf|properties|env|py|rb|php|go|java|kt|cs|rs|sh|bash|zsh|sql|html?|vue|svelte|astro|xml|gradle|tf|tfvars|txt|pem|key|md|lock)$/i;
const TEXT_NAME = /(?:^|\/)(?:\.env[\w.-]*|\.npmrc|\.pypirc|\.gitignore|Dockerfile[\w.-]*|Procfile|\.htpasswd|\.git-credentials|requirements[\w.-]*\.txt)$/i;
const SKIP_DIR = /(?:^|\/)(?:node_modules|\.git|dist|build|\.next|\.nuxt|\.svelte-kit|vendor|coverage|\.venv|venv|__pycache__|\.turbo|\.vercel|\.open-next|\.wrangler)\//;
const MAX_FILE = 400_000;
const MAX_KEPT_TOTAL = 24_000_000;

export function wantsContent(path: string, size: number): boolean {
  if (size === 0 || SKIP_DIR.test(path)) return false;
  if (/(?:^|\/)(?:package-lock\.json|yarn\.lock)$/.test(path)) return size <= 6_000_000;
  if (size > MAX_FILE) return false;
  if (/\.lock$/.test(path) || /(?:^|\/)pnpm-lock\.yaml$/.test(path)) return false;
  return TEXT_EXT.test(path) || TEXT_NAME.test(path);
}

/**
 * Tải mã nguồn qua tarball của GitHub (1 request, chỉ đọc). Kho công khai: codeload (không tính hạn mức API);
 * kho riêng tư: cần token chỉ-đọc, chỉ dùng cho request này và KHÔNG được lưu.
 */
export async function fetchRepoSnapshot(owner: string, repo: string, token: string | null, fetcher: typeof fetch = fetch): Promise<RepoSnapshot> {
  if (token && !TOKEN_RE.test(token)) throw new RepoError("invalid_token", "Token không hợp lệ. Hãy tạo token chỉ-đọc (Contents: Read-only) cho đúng kho này.");
  const url = token ? `https://api.github.com/repos/${owner}/${repo}/tarball` : `https://codeload.github.com/${owner}/${repo}/tar.gz/HEAD`;
  const headers: Record<string, string> = { "User-Agent": "VibeSec-Scanner", Accept: token ? "application/vnd.github+json" : "application/x-gzip" };
  if (token) { headers.Authorization = `Bearer ${token}`; headers["X-GitHub-Api-Version"] = "2022-11-28"; }

  let res: Response;
  try { res = await fetcher(url, { headers, redirect: "follow", signal: AbortSignal.timeout(25_000) }); }
  catch { throw new RepoError("network", "Không kết nối được tới GitHub. Vui lòng thử lại."); }

  if (res.status === 404) throw new RepoError("not_found", token ? "Không tìm thấy kho này hoặc token không có quyền đọc nó." : "Không tìm thấy kho này. Nếu là kho riêng tư, hãy mở mục \"Kho riêng tư\" và dán token chỉ-đọc.");
  if (res.status === 401 || res.status === 403) {
    if (res.headers.get("x-ratelimit-remaining") === "0") throw new RepoError("rate_limit", "GitHub đang giới hạn lượt tải. Hãy thử lại sau ít phút.");
    throw new RepoError("auth", "GitHub từ chối truy cập. Hãy kiểm tra token còn hạn và có quyền đọc nội dung kho (Contents: Read-only).");
  }
  if (res.status === 429) throw new RepoError("rate_limit", "GitHub đang giới hạn lượt tải. Hãy thử lại sau ít phút.");
  if (!res.ok || !res.body) throw new RepoError("network", `GitHub trả về lỗi ${res.status}. Vui lòng thử lại.`);
  const len = Number(res.headers.get("content-length") ?? 0);
  if (len > 80_000_000) throw new RepoError("too_big", "Kho quá lớn để quét (trên 80 MB nén). Hãy thử quét một thư mục con hoặc kho nhỏ hơn.");

  const files: SourceFile[] = [];
  const allPaths: string[] = [];
  const dec = new TextDecoder("utf-8", { fatal: false });
  let kept = 0, skippedLarge = 0;
  const { truncated, entries } = await untar(res.body.pipeThrough(new DecompressionStream("gzip")), {
    maxTotalBytes: 220_000_000, maxEntries: 40_000,
    onPath: (p, size) => { if (allPaths.length < 40_000 && !SKIP_DIR.test(p)) allPaths.push(p); if (size > MAX_FILE && TEXT_EXT.test(p) && !SKIP_DIR.test(p)) skippedLarge++; },
    wantEntry: (p, size) => kept + size <= MAX_KEPT_TOTAL && wantsContent(p, size),
    onFile: (p, data) => { kept += data.length; files.push({ path: p, content: dec.decode(data) }); },
  });
  if (entries === 0) throw new RepoError("empty", "Kho này không có file nào để quét.");
  return { owner, repo, files, allPaths, truncated, entries, skippedLarge };
}
