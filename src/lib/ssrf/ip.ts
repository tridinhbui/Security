/**
 * IP parsing and classification. Hand-rolled (no regex shortcuts) so that every
 * textual form we might meet is parsed to a number before being classified.
 *
 * Policy: an address is "public" only if it is global unicast and in none of the
 * special-purpose blocks below. Anything we cannot parse is treated as non-public.
 */

export type IpFamily = 4 | 6;
export interface ParsedIp {
  family: IpFamily;
  value: bigint;
}

/** Strict dotted-quad parser: exactly four decimal octets, no leading zeros ambiguity. */
export function parseIPv4(input: string): bigint | null {
  const parts = input.split(".");
  if (parts.length !== 4) return null;
  let out = 0n;
  for (const p of parts) {
    if (!/^(0|[1-9]\d{0,2})$/.test(p)) return null;
    const n = Number(p);
    if (n > 255) return null;
    out = (out << 8n) | BigInt(n);
  }
  return out;
}

/**
 * Lenient IPv4 parser matching the legacy inet_aton behaviours that some
 * resolvers/libraries still accept: 1–4 parts, hex (0x), octal (leading 0).
 * We never *connect* using these forms, but we parse them so that anything that
 * even looks like one is classified correctly instead of slipping through as a "hostname".
 */
export function parseLegacyIPv4(input: string): bigint | null {
  if (input.endsWith(".")) input = input.slice(0, -1);
  if (input === "") return null;
  const parts = input.split(".");
  if (parts.length < 1 || parts.length > 4) return null;
  const nums: bigint[] = [];
  for (const p of parts) {
    let n: bigint;
    if (/^0x[0-9a-f]*$/i.test(p)) {
      if (p.length === 2) return null;
      n = BigInt(p);
    } else if (/^0[0-7]+$/.test(p)) {
      n = BigInt("0o" + p.slice(1));
    } else if (/^(0|[1-9]\d*)$/.test(p)) {
      n = BigInt(p);
    } else return null;
    nums.push(n);
  }
  const last = nums[nums.length - 1]!;
  const leading = nums.slice(0, -1);
  if (leading.some((n) => n > 255n)) return null;
  const lastBits = BigInt(8 * (5 - nums.length));
  if (last >= 1n << lastBits) return null;
  let out = last;
  leading.forEach((n, i) => {
    out |= n << BigInt(24 - 8 * i);
  });
  return out;
}

/** IPv6 parser supporting `::` compression and an embedded dotted IPv4 tail. Rejects zone IDs. */
export function parseIPv6(input: string): bigint | null {
  let s = input;
  if (s.startsWith("[") && s.endsWith("]")) s = s.slice(1, -1);
  if (s.includes("%") || s.length < 2 || s.length > 45) return null;
  if (!/^[0-9a-f:.]+$/i.test(s)) return null;

  let tail: bigint[] = [];
  const lastColon = s.lastIndexOf(":");
  if (s.includes(".")) {
    const v4 = parseIPv4(s.slice(lastColon + 1));
    if (v4 === null) return null;
    tail = [(v4 >> 16n) & 0xffffn, v4 & 0xffffn];
    s = s.slice(0, lastColon + 1) + "0:0"; // placeholder groups, replaced below
  }

  const halves = s.split("::");
  if (halves.length > 2) return null;
  const parseGroups = (str: string): number[] | null => {
    if (str === "") return [];
    const groups = str.split(":");
    const out: number[] = [];
    for (const g of groups) {
      if (!/^[0-9a-f]{1,4}$/i.test(g)) return null;
      out.push(parseInt(g, 16));
    }
    return out;
  };
  const head = parseGroups(halves[0]!);
  const rest = halves.length === 2 ? parseGroups(halves[1]!) : [];
  if (head === null || rest === null) return null;

  let groups: number[];
  if (halves.length === 2) {
    const missing = 8 - head.length - rest.length;
    if (missing < 1) return null;
    groups = [...head, ...new Array<number>(missing).fill(0), ...rest];
  } else {
    if (head.length !== 8) return null;
    groups = head;
  }
  if (groups.length !== 8) return null;
  if (tail.length) {
    groups[6] = Number(tail[0]);
    groups[7] = Number(tail[1]);
  }
  return groups.reduce((acc, g) => (acc << 16n) | BigInt(g), 0n);
}

export function parseIp(input: string): ParsedIp | null {
  const v4 = parseIPv4(input);
  if (v4 !== null) return { family: 4, value: v4 };
  const v6 = parseIPv6(input);
  if (v6 !== null) return { family: 6, value: v6 };
  return null;
}

// ---------------------------------------------------------------- block lists

type Cidr = readonly [family: IpFamily, base: string, prefix: number, label: string];

const BLOCKED: readonly Cidr[] = [
  // IPv4
  [4, "0.0.0.0", 8, "this-network"],
  [4, "10.0.0.0", 8, "rfc1918"],
  [4, "100.64.0.0", 10, "cgnat"],
  [4, "127.0.0.0", 8, "loopback"],
  [4, "169.254.0.0", 16, "link-local/metadata"],
  [4, "172.16.0.0", 12, "rfc1918"],
  [4, "192.0.0.0", 24, "ietf-protocol"],
  [4, "192.0.2.0", 24, "documentation"],
  [4, "192.88.99.0", 24, "6to4-relay"],
  [4, "192.168.0.0", 16, "rfc1918"],
  [4, "198.18.0.0", 15, "benchmark"],
  [4, "198.51.100.0", 24, "documentation"],
  [4, "203.0.113.0", 24, "documentation"],
  [4, "224.0.0.0", 4, "multicast"],
  [4, "240.0.0.0", 4, "reserved"],
  // IPv6
  [6, "::", 128, "unspecified"],
  [6, "::1", 128, "loopback"],
  [6, "::", 96, "ipv4-compatible (deprecated)"],
  [6, "::ffff:0:0", 96, "ipv4-mapped"], // also re-checked via embedded address below
  [6, "64:ff9b::", 96, "nat64"], // re-checked via embedded address below
  [6, "64:ff9b:1::", 48, "nat64-local"],
  [6, "100::", 64, "discard"],
  [6, "2001::", 23, "ietf-protocol/teredo"],
  [6, "2001:db8::", 32, "documentation"],
  [6, "2002::", 16, "6to4"],
  [6, "3fff::", 20, "documentation"],
  [6, "fc00::", 7, "unique-local"],
  [6, "fe80::", 10, "link-local"],
  [6, "fec0::", 10, "site-local (deprecated)"],
  [6, "ff00::", 8, "multicast"],
];

const compiled = BLOCKED.map(([family, base, prefix, label]) => {
  const value = family === 4 ? parseIPv4(base)! : parseIPv6(base)!;
  const bits = family === 4 ? 32 : 128;
  const shift = BigInt(bits - prefix);
  return { family, net: value >> shift, shift, label };
});

/** 2000::/3 is the only IPv6 range currently allocated as global unicast. */
const GLOBAL_UNICAST_V6_NET = parseIPv6("2000::")! >> 125n;

export interface IpClassification {
  public: boolean;
  /** Why it was blocked (for audit logs); undefined when public. */
  reason?: string;
}

/** Extract an IPv4 address embedded in an IPv6 transition address, if any. */
function embeddedIPv4(v6: bigint): bigint | null {
  const low32 = v6 & 0xffffffffn;
  const top96 = v6 >> 32n;
  if (top96 === 0xffffn) return low32; // ::ffff:a.b.c.d
  if (top96 === 0n) return low32; // ::a.b.c.d (deprecated compatible)
  if (v6 >> 32n === parseIPv6("64:ff9b::")! >> 32n) return low32; // 64:ff9b::/96
  return null;
}

export function classifyIp(ip: ParsedIp): IpClassification {
  if (ip.family === 6) {
    const emb = embeddedIPv4(ip.value);
    if (emb !== null) {
      const inner = classifyIp({ family: 4, value: emb });
      // Even a "public" embedded v4 is blocked: these forms are a classic filter bypass.
      return { public: false, reason: inner.public ? "ipv6-embedded-ipv4" : `ipv6-embedded:${inner.reason}` };
    }
    if (ip.value >> 125n !== GLOBAL_UNICAST_V6_NET) return { public: false, reason: "not-global-unicast" };
  }
  for (const c of compiled) {
    if (c.family === ip.family && ip.value >> c.shift === c.net) return { public: false, reason: c.label };
  }
  return { public: true };
}

export function classifyIpString(input: string): IpClassification {
  const parsed = parseIp(input);
  if (!parsed) return { public: false, reason: "unparseable-ip" };
  return classifyIp(parsed);
}

/** True when a hostname token is an IP literal in any form we know (strict or legacy). */
export function looksLikeIpLiteral(host: string): boolean {
  const h = host.startsWith("[") ? host : host.replace(/\.$/, "");
  if (h.startsWith("[")) return true;
  if (parseIp(h) !== null) return true;
  return parseLegacyIPv4(h) !== null;
}

/** Classify any IP literal (including legacy encodings). Non-literals return null. */
export function classifyLiteral(host: string): IpClassification | null {
  if (host.startsWith("[")) return classifyIpString(host);
  const h = host.replace(/\.$/, "");
  const strict = parseIp(h);
  if (strict) return classifyIp(strict);
  const legacy = parseLegacyIPv4(h);
  if (legacy !== null) return classifyIp({ family: 4, value: legacy });
  return null;
}
