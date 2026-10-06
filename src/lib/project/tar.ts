/**
 * Đọc luồng tar (đã giải nén gzip) theo kiểu streaming: bộ nhớ chỉ giữ nội dung các file được chọn.
 * Hỗ trợ ustar (prefix), pax (path/size) và GNU long name — đủ cho tarball của GitHub.
 */

export interface UntarOptions {
  /** Quyết định có đọc nội dung file này không (theo đường dẫn đã bỏ thư mục gốc và kích thước). */
  wantEntry(path: string, size: number): boolean;
  onFile(path: string, data: Uint8Array): void;
  /** Gọi cho MỌI file thường (kể cả file không đọc nội dung) để lập danh sách đường dẫn. */
  onPath?(path: string, size: number): void;
  /** Dừng khi đã đọc quá số byte này (chống tarball khổng lồ). */
  maxTotalBytes: number;
  maxEntries: number;
}

export interface UntarResult { truncated: boolean; entries: number }

class ByteReader {
  private chunks: Uint8Array[] = [];
  private len = 0;
  private ended = false;
  consumed = 0;
  constructor(private readonly r: ReadableStreamDefaultReader<Uint8Array>) {}

  private async fill(n: number) {
    while (this.len < n && !this.ended) {
      const { value, done } = await this.r.read();
      if (done) { this.ended = true; break; }
      if (value.length) { this.chunks.push(value); this.len += value.length; }
    }
  }
  private take(n: number): Uint8Array {
    const out = new Uint8Array(n);
    let off = 0;
    while (off < n) {
      const c = this.chunks[0]!;
      const t = Math.min(c.length, n - off);
      out.set(c.subarray(0, t), off);
      off += t;
      if (t === c.length) this.chunks.shift(); else this.chunks[0] = c.subarray(t);
    }
    this.len -= n;
    this.consumed += n;
    return out;
  }
  cancel() { return this.r.cancel().catch(() => undefined); }
  /** Đọc đúng n byte; null nếu hết dữ liệu trước khi đủ. */
  async read(n: number): Promise<Uint8Array | null> {
    await this.fill(n);
    return this.len >= n ? this.take(n) : null;
  }
  async skip(n: number): Promise<boolean> {
    while (n > 0) {
      if (this.len === 0) { await this.fill(1); if (this.len === 0) return false; }
      const t = Math.min(n, this.len);
      this.take(t);
      n -= t;
    }
    return true;
  }
}

const dec = new TextDecoder();
const str = (b: Uint8Array, from: number, len: number) => {
  const s = b.subarray(from, from + len);
  const z = s.indexOf(0);
  return dec.decode(z === -1 ? s : s.subarray(0, z));
};

function parsePax(data: Uint8Array): Record<string, string> {
  const out: Record<string, string> = {};
  const text = dec.decode(data);
  let i = 0;
  while (i < text.length) {
    const sp = text.indexOf(" ", i);
    if (sp === -1) break;
    const n = Number(text.slice(i, sp));
    if (!Number.isFinite(n) || n <= 0) break;
    const rec = text.slice(sp + 1, i + n - 1); // bỏ "\n" cuối
    const eq = rec.indexOf("=");
    if (eq > 0) out[rec.slice(0, eq)] = rec.slice(eq + 1);
    i += n;
  }
  return out;
}

/** Bỏ thư mục gốc `repo-sha/` mà GitHub thêm vào, và chặn đường dẫn thoát thư mục. */
function cleanPath(p: string): string | null {
  const rest = p.split("/").slice(1).join("/");
  if (!rest || rest.split("/").includes("..") || rest.startsWith("/")) return null;
  return rest;
}

export async function untar(stream: ReadableStream<Uint8Array>, o: UntarOptions): Promise<UntarResult> {
  const reader = new ByteReader(stream.getReader());
  let entries = 0, truncated = false;
  let pendingPath: string | null = null, pendingSize: number | null = null;
  try {
    for (;;) {
      if (reader.consumed > o.maxTotalBytes || entries > o.maxEntries) { truncated = true; break; }
      const h = await reader.read(512);
      if (!h || h.every((b) => b === 0)) break;
      const type = String.fromCharCode(h[156] || 48);
      let size = parseInt(str(h, 124, 12).trim() || "0", 8);
      if (!Number.isFinite(size) || size < 0) break;
      let name = str(h, 0, 100);
      if (str(h, 257, 5) === "ustar") { const prefix = str(h, 345, 155); if (prefix) name = `${prefix}/${name}`; }
      const pad = (512 - (size % 512)) % 512;

      if (type === "x" || type === "g" || type === "L") {
        if (size > 1_000_000) { truncated = true; break; }
        const data = await reader.read(size);
        if (!data || !(await reader.skip(pad))) break;
        if (type === "x") { const p = parsePax(data); if (p.path) pendingPath = p.path; if (p.size) pendingSize = Number(p.size); }
        else if (type === "L") pendingPath = str(data, 0, data.length);
        continue;
      }

      if (pendingPath) { name = pendingPath; pendingPath = null; }
      if (pendingSize !== null) { size = pendingSize; pendingSize = null; }
      const padded = (512 - (size % 512)) % 512;
      const isFile = type === "0" || type === "\0" || type === "7";
      const path = isFile ? cleanPath(name) : null;
      if (path) {
        entries++;
        o.onPath?.(path, size);
        if (o.wantEntry(path, size)) {
          const data = await reader.read(size);
          if (!data) break;
          o.onFile(path, data);
        } else if (!(await reader.skip(size))) break;
      } else if (!(await reader.skip(size))) break;
      if (!(await reader.skip(padded))) break;
    }
  } finally {
    await reader.cancel();
  }
  return { truncated, entries };
}
