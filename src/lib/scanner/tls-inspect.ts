import tls from "node:tls";
import { resolvePublicAddresses, type ResolvedAddress, type Resolver } from "../ssrf/dns";
import { systemResolver } from "../ssrf/dns-node";
import { CERT_ERRORS, describeCert } from "../ssrf/fetch";
import type { TlsInfo } from "../ssrf/types";
import { normalizeTargetUrl, SsrfError } from "../ssrf/url";
import { probeLegacyTlsVersion } from "./collect";
import type { Observations } from "./types";

/**
 * Phần DUY NHẤT của lượt quét cần container: đọc chứng chỉ, phiên bản TLS và ALPN (node:tls) — Worker không làm được.
 * Một lần bắt tay + hai thăm dò TLS cũ, chỉ vài giây. Kết nối tới IP công khai đã kiểm tra (không phân giải lại).
 */
export interface TlsInspection {
  ok: true;
  tls: TlsInfo;
  certError?: { code: string; message: string };
  legacyTls: NonNullable<Observations["legacyTls"]>;
  resolved: string[];
}
export type TlsInspectResult = TlsInspection | { ok: false; code: string };

export interface InspectDeps {
  resolver?: Resolver;
  dnsCache?: Map<string, { at: number; addrs: ResolvedAddress[] }>;
  legacyProbe?: typeof probeLegacyTlsVersion;
}

function handshake(host: string, ip: string): Promise<{ tls: TlsInfo; h2: boolean; certError?: { code: string; message: string } } | { code: string }> {
  return new Promise((resolve) => {
    let done = false;
    const finish = (v: Awaited<ReturnType<typeof handshake>>) => { if (!done) { done = true; clearTimeout(timer); resolve(v); } };
    const socket = tls.connect({ host: ip, port: 443, servername: host, ALPNProtocols: ["h2", "http/1.1"], rejectUnauthorized: false }, () => {
      const info = describeCert(socket);
      const h2 = socket.alpnProtocol === "h2";
      let certError: { code: string; message: string } | undefined;
      if (!socket.authorized) {
        const code = String(socket.authorizationError ?? "CERT_ERROR");
        certError = { code: CERT_ERRORS.has(code) ? code : "UNABLE_TO_VERIFY_LEAF_SIGNATURE", message: "Không xác minh được chứng chỉ TLS." };
      }
      socket.destroy();
      finish({ tls: info, h2, certError });
    });
    const timer = setTimeout(() => { socket.destroy(); finish({ code: "ETIMEDOUT" }); }, 7000);
    socket.on("error", (e) => finish({ code: (e as NodeJS.ErrnoException).code ?? "ERR" }));
  });
}

/** Ném SsrfError nếu host không hợp lệ/không công khai (cùng các lớp kiểm tra như bộ quét đầy đủ). */
export async function inspectTls(host: string, deps: InspectDeps = {}): Promise<TlsInspectResult> {
  const target = normalizeTargetUrl(`https://${host}`);
  const addrs = await resolvePublicAddresses(target.host, deps.resolver ?? systemResolver, deps.dnsCache);
  const ip = addrs[0]!.address;
  const hs = await handshake(target.host, ip);
  if ("code" in hs) return { ok: false, code: hs.code };
  let tls10: boolean | null = null, tls11: boolean | null = null;
  if (!hs.certError) {
    const probe = deps.legacyProbe ?? probeLegacyTlsVersion;
    [tls10, tls11] = await Promise.all([probe(target.host, ip, "TLSv1"), probe(target.host, ip, "TLSv1.1")]);
  }
  return { ok: true, tls: hs.tls, certError: hs.certError, legacyTls: { tls10, tls11, h2: hs.h2 }, resolved: addrs.map((a) => a.address) };
}

export { SsrfError };
