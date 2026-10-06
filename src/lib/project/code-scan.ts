import { analyzeSource } from "./code-analyze";
import { findOutdated, findVulns, lockfileItem, outdatedItem, parseManifests, vulnItems } from "./deps";
import { fetchRepoSnapshot, parseRepoInput, RepoError } from "./github";
import { item, scoreItems, type ProjectItem } from "./types";

export interface CodeScanResult { label: string; items: ProjectItem[]; meta: { files: number; entries: number; packages: number; truncated: boolean; skippedLarge: number; privateRepo: boolean } }

/**
 * Quét mã nguồn từ GitHub (chỉ đọc): tải tarball → phân tích tĩnh → đối chiếu thư viện với OSV.dev / npm registry.
 * Token (nếu có) chỉ dùng trong lời gọi này, không được ghi log hay lưu.
 */
export async function runCodeScan(input: { repo: string; token?: string | null }, fetcher: typeof fetch = fetch): Promise<CodeScanResult> {
  const ref = parseRepoInput(input.repo);
  if (!ref) throw new RepoError("invalid_repo", "Hãy nhập kho GitHub dạng owner/repo hoặc dán địa chỉ https://github.com/owner/repo.");
  const token = input.token?.trim() || null;
  const snap = await fetchRepoSnapshot(ref.owner, ref.repo, token, fetcher);

  const items = analyzeSource({ files: snap.files, allPaths: snap.allPaths });

  const parsed = parseManifests(snap.files);
  const lock = lockfileItem(parsed);
  if (lock) items.push(lock);
  if (parsed.deps.length) {
    const [vulns, outdated] = await Promise.all([findVulns(parsed.deps, fetcher), findOutdated(parsed, fetcher)]);
    items.push(...vulnItems(vulns.hits, parsed, vulns.ok));
    const o = outdatedItem(outdated, parsed);
    if (o) items.push(o);
  } else {
    items.push(item({ id: "deps-none", group: "Thư viện (dependencies)", source: "code", title: "Không tìm thấy danh sách thư viện để kiểm tra", severity: "info", status: "unknown", summary: "Không thấy package.json hoặc requirements.txt. Phiên bản này kiểm tra thư viện npm và Python (pip).", why: "Thư viện cũ có lỗ hổng đã công bố là lối vào phổ biến của kẻ tấn công." }));
  }
  if (snap.truncated || snap.skippedLarge) {
    items.push(item({ id: "scan-partial", group: "Phạm vi quét", source: "code", title: "Một phần kho chưa được quét", severity: "info", status: "unknown", summary: `${snap.truncated ? "Kho rất lớn nên chỉ quét phần đầu. " : ""}${snap.skippedLarge ? `${snap.skippedLarge} file quá lớn đã bị bỏ qua.` : ""}`.trim(), why: "Kết quả có thể thiếu những file không được quét." }));
  }
  return { label: `${snap.owner}/${snap.repo}`, items, meta: { files: snap.files.length, entries: snap.entries, packages: parsed.deps.length, truncated: snap.truncated, skippedLarge: snap.skippedLarge, privateRepo: !!token } };
}

export { scoreItems };
