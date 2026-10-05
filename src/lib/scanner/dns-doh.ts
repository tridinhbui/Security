import type { DnsInfo } from "./types";

/**
 * Thông tin DNS (SPF/DMARC/MTA-STS/CAA/MX/NS/CNAME/DNSSEC) qua DNS-over-HTTPS của Cloudflare.
 * Thuần fetch (không node:dns) nên chạy được trong Worker. Chỉ hỏi bộ phân giải công cộng, không hỏi máy chủ của mục tiêu.
 */
const TYPE = { NS: 2, CNAME: 5, MX: 15, TXT: 16, CAA: 257 } as const;
type Answer = { type: number; data: string };
type Result = { ok: true; answers: Answer[]; ad: boolean } | { ok: false };

async function query(fetchImpl: typeof fetch, name: string, type: number, dnssec = false): Promise<Result> {
  try {
    const res = await fetchImpl(`https://cloudflare-dns.com/dns-query?name=${encodeURIComponent(name)}&type=${type}${dnssec ? "&do=1" : ""}`, {
      headers: { accept: "application/dns-json" },
      signal: AbortSignal.timeout(4000),
    });
    if (!res.ok) return { ok: false };
    const body = (await res.json()) as { Status: number; AD?: boolean; Answer?: Answer[] };
    if (body.Status === 3) return { ok: true, answers: [], ad: false }; // NXDOMAIN = không có bản ghi
    if (body.Status !== 0) return { ok: false };
    return { ok: true, answers: (body.Answer ?? []).filter((a) => a.type === type), ad: body.AD === true };
  } catch {
    return { ok: false };
  }
}

const stripDot = (s: string) => s.replace(/\.$/, "");
/** "\"abc\" \"def\"" → "abcdef" (TXT dài bị chia thành nhiều chuỗi). */
export const joinTxt = (data: string) => [...data.matchAll(/"((?:[^"\\]|\\.)*)"/g)].map((m) => m[1]!.replace(/\\(.)/g, "$1")).join("") || data;

/** CAA có thể trả về dạng chữ `0 issue "x"` hoặc dạng nhị phân RFC 3597 `\# 22 0005…`. */
export function parseCaa(data: string): string | null {
  const text = /^(\d+)\s+(issuewild|issue|iodef)\s+"?([^"]*)"?$/i.exec(data.trim());
  if (text) return `${Number(text[1])} ${text[2]!.toLowerCase() === "iodef" ? "iodef" : `${text[2]!.toLowerCase()} "${text[3]}"`}`;
  const hex = /^\\#\s+\d+\s+([0-9a-f]+)$/i.exec(data.trim().replace(/\s+/g, " "))?.[1];
  if (!hex || hex.length < 4) return null;
  const bytes = hex.match(/../g)!.map((h) => parseInt(h, 16));
  const flags = bytes[0]!, tagLen = bytes[1]!;
  const tag = String.fromCharCode(...bytes.slice(2, 2 + tagLen));
  const value = String.fromCharCode(...bytes.slice(2 + tagLen));
  return `${flags} ${tag === "iodef" ? "iodef" : `${tag} "${value}"`}`;
}

export function createDohDnsLookup(fetchImpl: typeof fetch = fetch) {
  return async function lookupDnsMetadataDoh(domain: string, host: string = domain): Promise<DnsInfo> {
    const [txtR, dmarcR, mtaR, caaR, cnameR, mxR, nsR, dnssecR] = await Promise.all([
      query(fetchImpl, domain, TYPE.TXT),
      query(fetchImpl, `_dmarc.${domain}`, TYPE.TXT),
      query(fetchImpl, `_mta-sts.${domain}`, TYPE.TXT),
      query(fetchImpl, domain, TYPE.CAA),
      query(fetchImpl, host, TYPE.CNAME),
      query(fetchImpl, domain, TYPE.MX),
      query(fetchImpl, domain, TYPE.NS),
      query(fetchImpl, domain, 1, true), // DNSSEC: cờ AD của truy vấn A
    ]);
    const txts = txtR.ok ? txtR.answers.map((a) => joinTxt(a.data)) : undefined;
    const dmarc = dmarcR.ok ? dmarcR.answers.map((a) => joinTxt(a.data)) : undefined;
    const mta = mtaR.ok ? mtaR.answers.map((a) => joinTxt(a.data)) : undefined;
    const spfAll = txts?.filter((t) => /^v=spf1\b/i.test(t)) ?? [];
    const cname = cnameR.ok ? cnameR.answers.map((a) => stripDot(a.data)) : null;
    return {
      domain,
      caa: caaR.ok ? caaR.answers.map((a) => parseCaa(a.data)).filter((x): x is string => !!x) : null,
      spf: txts === undefined ? undefined : (spfAll[0] ?? null),
      spfRecords: spfAll.length,
      dmarc: dmarc === undefined ? undefined : (dmarc.find((t) => /^v=DMARC1\b/i.test(t)) ?? null),
      mtaSts: mta === undefined ? undefined : mta.some((t) => /^v=STSv1\b/i.test(t)),
      cname: cname && cname.length ? cname : null,
      mx: mxR.ok ? mxR.answers.map((a) => stripDot(a.data.split(/\s+/)[1] ?? "")).filter(Boolean) : null,
      ns: nsR.ok ? nsR.answers.map((a) => stripDot(a.data)) : null,
      dnssec: dnssecR.ok ? dnssecR.ad : undefined,
    };
  };
}
