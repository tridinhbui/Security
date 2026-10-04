import { classifyIpString, classifyLiteral } from "./ip";
import { SsrfError } from "./url";

export interface ResolvedAddress {
  address: string;
  family: 4 | 6;
}

/** Injectable: the system resolver (container), DNS-over-HTTPS (Worker preflight) or a test double. */
export type Resolver = (host: string) => Promise<ResolvedAddress[]>;

/**
 * Resolve a hostname and require EVERY answer to be public. If any answer is private we
 * refuse the whole host: a mixed answer set is a rebinding/round-robin attack signature,
 * and refusing is safer than hoping the OS picks the public one.
 *
 * The returned list is what the HTTP client is pinned to, so the address validated here
 * is the address connected to (no second lookup → no TOCTOU rebinding window).
 */
export async function resolvePublicAddresses(
  host: string,
  resolver: Resolver,
  cache?: Map<string, { at: number; addrs: ResolvedAddress[] }>,
): Promise<ResolvedAddress[]> {
  const literal = classifyLiteral(host);
  if (literal) {
    if (!literal.public) throw new SsrfError("non_public_ip", "That address is not publicly routable.", literal.reason);
    // Re-derive canonical form through the URL parser so we pin the real address.
    const bare = new URL(`http://${host.includes(":") && !host.startsWith("[") ? `[${host}]` : host}`).hostname;
    const addr = bare.replace(/^\[|\]$/g, "");
    return [{ address: addr, family: addr.includes(":") ? 6 : 4 }];
  }

  const hit = cache?.get(host);
  if (hit && Date.now() - hit.at < 5 * 60_000) return hit.addrs;

  let addrs: ResolvedAddress[];
  try {
    addrs = await resolver(host);
  } catch (e) {
    throw new SsrfError("dns_failed", "We couldn't resolve that domain.", (e as NodeJS.ErrnoException).code);
  }
  if (addrs.length === 0) throw new SsrfError("dns_failed", "That domain has no IP address.");

  const bad = addrs.filter((a) => !classifyIpString(a.address).public);
  if (bad.length === addrs.length) {
    throw new SsrfError("non_public_ip", "That domain resolves to a non-public address.", classifyIpString(bad[0]!.address).reason);
  }
  if (bad.length > 0) {
    throw new SsrfError("dns_mixed_answers", "That domain resolves to both public and non-public addresses.", bad[0]!.address);
  }
  cache?.set(host, { at: Date.now(), addrs });
  return addrs;
}

/**
 * Build a `lookup` for http.request/tls.connect that can only ever return the
 * pre-validated addresses. Anything else is a hard error.
 */
export function pinnedLookup(addrs: ResolvedAddress[], allowNonPublic = false) {
  // Re-check at connect time; cheap and keeps this function safe if misused.
  const safe = allowNonPublic ? addrs : addrs.filter((a) => classifyIpString(a.address).public);
  return (
    _hostname: string,
    options: { all?: boolean; family?: number } | number | undefined,
    cb: (err: NodeJS.ErrnoException | null, address?: string | ResolvedAddress[], family?: number) => void,
  ) => {
    const opts = typeof options === "object" && options ? options : {};
    let list = safe;
    if (opts.family === 4 || opts.family === 6) list = safe.filter((a) => a.family === opts.family);
    if (list.length === 0) {
      const err = new Error("No pinned public address available") as NodeJS.ErrnoException;
      err.code = "ENOTFOUND";
      return cb(err);
    }
    if (opts.all) return cb(null, list);
    cb(null, list[0]!.address, list[0]!.family);
  };
}
