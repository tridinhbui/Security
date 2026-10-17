/** Metadata phiên bản Worker (binding `version_metadata`). Chỉ gồm ID/thời điểm tải lên, không có cấu hình hay bí mật. */
export interface WorkerVersionMetadata { id?: unknown; tag?: unknown; timestamp?: unknown }
export interface VersionInfo {
  /** Commit đã được nhúng vào bản dựng ("unknown" nếu build không có biến môi trường CI). */
  commit: string;
  /** Thời điểm chạy `next build`. */
  builtAt: string;
  /** ID phiên bản Cloudflare Worker ĐANG phục vụ request này (null khi chạy local, không có binding). */
  workerVersionId: string | null;
  /** Thời điểm phiên bản đó được tải lên Cloudflare. */
  workerVersionUploadedAt: string | null;
}

const str = (v: unknown) => (typeof v === "string" && v.length > 0 && v.length <= 80 ? v : null);
/** Chỉ nhận SHA hex 7–40 ký tự; mọi thứ khác (kể cả biến môi trường lạ) bị đổi thành "unknown". */
export const cleanSha = (v: unknown) => (typeof v === "string" && /^[0-9a-f]{7,40}$/i.test(v) ? v.toLowerCase() : "unknown");
const cleanTime = (v: unknown) => { const s = str(v); return s && !Number.isNaN(Date.parse(s)) ? s : null; };

export function versionInfo(meta: WorkerVersionMetadata | null | undefined, build: { sha?: unknown; time?: unknown }): VersionInfo {
  const id = str(meta?.id);
  return {
    commit: cleanSha(build.sha),
    builtAt: cleanTime(build.time) ?? "unknown",
    workerVersionId: id && /^[0-9a-f-]{8,64}$/i.test(id) ? id.toLowerCase() : null,
    workerVersionUploadedAt: cleanTime(meta?.timestamp),
  };
}
