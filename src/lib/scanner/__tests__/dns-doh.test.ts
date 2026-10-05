import { describe, expect, it } from "vitest";
import { createDohDnsLookup, joinTxt, parseCaa } from "../dns-doh";

const reply = (table: Record<string, { Status?: number; AD?: boolean; Answer?: { type: number; data: string }[] }>): typeof fetch =>
  (async (input: RequestInfo | URL) => {
    const u = new URL(String(input));
    const key = `${u.searchParams.get("name")}|${u.searchParams.get("type")}`;
    const body = table[key] ?? { Status: 0, Answer: [] };
    return new Response(JSON.stringify({ Status: 0, ...body }), { headers: { "content-type": "application/dns-json" } });
  }) as typeof fetch;

describe("DoH DNS metadata", () => {
  it("phân tích SPF/DMARC/MTA-STS/CAA/MX/NS/DNSSEC", async () => {
    const f = reply({
      "example.com|16": { Answer: [{ type: 16, data: '"v=spf1 include:_spf.google.com " "-all"' }, { type: 16, data: '"google-site-verification=abc"' }] },
      "_dmarc.example.com|16": { Answer: [{ type: 16, data: '"v=DMARC1; p=reject"' }] },
      "_mta-sts.example.com|16": { Answer: [{ type: 16, data: '"v=STSv1; id=1"' }] },
      "example.com|257": { Answer: [{ type: 257, data: '0 issue "letsencrypt.org"' }] },
      "example.com|15": { Answer: [{ type: 15, data: "10 mx.example.com." }] },
      "example.com|2": { Answer: [{ type: 2, data: "ns1.example.com." }] },
      "example.com|1": { AD: true, Answer: [{ type: 1, data: "93.184.216.34" }] },
    });
    const d = await createDohDnsLookup(f)("example.com");
    expect(d).toMatchObject({ spf: "v=spf1 include:_spf.google.com -all", spfRecords: 1, dmarc: "v=DMARC1; p=reject", mtaSts: true, caa: ['0 issue "letsencrypt.org"'], mx: ["mx.example.com"], ns: ["ns1.example.com"], dnssec: true, cname: null });
  });
  it("lỗi DoH → undefined (không kết luận 'thiếu'), NXDOMAIN → không có bản ghi", async () => {
    const f = (async (input: RequestInfo | URL) => {
      const name = new URL(String(input)).searchParams.get("name");
      return name === "_dmarc.example.com" ? new Response("x", { status: 500 }) : new Response(JSON.stringify({ Status: 3 }));
    }) as typeof fetch;
    const d = await createDohDnsLookup(f)("example.com");
    expect(d.dmarc).toBeUndefined();
    expect(d.spf).toBeNull();
    expect(d.mx).toEqual([]);
  });
  it("CAA dạng nhị phân RFC 3597 và TXT nhiều đoạn", () => {
    // flags=0, tag=issue, value=letsencrypt.org
    const hex = "00" + "05" + Buffer.from("issue").toString("hex") + Buffer.from("letsencrypt.org").toString("hex");
    expect(parseCaa(`\\# ${hex.length / 2} ${hex}`)).toBe('0 issue "letsencrypt.org"');
    expect(joinTxt('"ab" "cd"')).toBe("abcd");
  });
});
