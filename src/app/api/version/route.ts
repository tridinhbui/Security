import { getCloudflareContext } from "@opennextjs/cloudflare";
import { json } from "@/lib/http/guards";
import { versionInfo, type WorkerVersionMetadata } from "@/lib/version";

export const dynamic = "force-dynamic";

/**
 * Phiên bản đang phục vụ: commit nhúng lúc build + ID phiên bản Worker do Cloudflare cấp lúc chạy.
 * Công khai và chỉ đọc; không chứa cấu hình, biến môi trường hay bí mật.
 * "Build thành công" ≠ "đang phục vụ": chỉ `workerVersionId` ở đây (đọc từ binding lúc chạy) chứng minh bản đang chạy.
 */
export async function GET() {
  let meta: WorkerVersionMetadata | undefined;
  try {
    const { env } = await getCloudflareContext({ async: true });
    meta = (env as unknown as { CF_VERSION_METADATA?: WorkerVersionMetadata }).CF_VERSION_METADATA;
  } catch { /* chạy ngoài Workers: không có binding */ }
  return json(versionInfo(meta, { sha: process.env.BUILD_COMMIT_SHA, time: process.env.BUILD_TIME }));
}
