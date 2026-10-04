import dns from "node:dns/promises";
import type { Resolver } from "./dns";

/** System resolver. Node-only: used inside the scanner container, never bundled into the Worker. */
export const systemResolver: Resolver = async (host) => {
  const res = await dns.lookup(host, { all: true, verbatim: true });
  return res.map((r) => ({ address: r.address, family: r.family === 6 ? 6 : 4 }));
};
