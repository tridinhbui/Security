import { describe, expect, it } from "vitest";
import { normalizeTargetUrl, SsrfError, validateRequestUrl } from "../url";

const code = (fn: () => unknown) => {
  try {
    fn();
  } catch (e) {
    return (e as SsrfError).code;
  }
  return "no-error";
};

describe("normalizeTargetUrl — accepted", () => {
  it("adds https and strips query/fragment/default port", () => {
    const t = normalizeTargetUrl("  Example.COM:443/Path/?token=abc#frag ");
    expect(t.url).toBe("https://example.com/Path/");
    expect(t.host).toBe("example.com");
    expect(t.port).toBe(443);
  });
  it("keeps http and explicit scheme", () => {
    expect(normalizeTargetUrl("http://example.com").url).toBe("http://example.com/");
  });
  it("strips trailing dot and converts IDN to punycode", () => {
    expect(normalizeTargetUrl("https://example.com./").host).toBe("example.com");
    expect(normalizeTargetUrl("https://bücher.example.org").host).toBe("xn--bcher-kva.example.org");
  });
  it("accepts a public IP literal", () => {
    expect(normalizeTargetUrl("http://93.184.216.34/").host).toBe("93.184.216.34");
  });
});

describe("normalizeTargetUrl — scheme/credentials/port", () => {
  it.each([
    ["ftp://example.com", "scheme_not_allowed"],
    ["file:///etc/passwd", "scheme_not_allowed"],
    ["gopher://example.com", "scheme_not_allowed"],
    ["javascript:alert(1)", "invalid_url"],
    ["data:text/html,hi", "invalid_url"],
    ["https://user:pw@example.com", "credentials_not_allowed"],
    ["https://user@example.com", "credentials_not_allowed"],
    ["https://example.com:8080", "port_not_allowed"],
    ["http://example.com:22", "port_not_allowed"],
    ["https://example.com:6379", "port_not_allowed"],
    ["", "invalid_url"],
    ["   ", "invalid_url"],
    ["exa mple.com", "invalid_url"],
    ["https://example.com/\nHost: evil", "invalid_url"],
    ["https://", "invalid_url"],
  ])("%j → %s", (input, expected) => expect(code(() => normalizeTargetUrl(input))).toBe(expected));
  it("rejects over-long URLs", () => {
    expect(code(() => normalizeTargetUrl("https://example.com/" + "a".repeat(3000)))).toBe("invalid_url");
  });
});

describe("normalizeTargetUrl — loopback/private IP encodings are blocked", () => {
  it.each([
    "http://127.0.0.1", "http://127.1", "http://0.0.0.0", "http://0", "http://2130706433", "http://0x7f000001",
    "http://0x7f.0x0.0x0.0x1", "http://017700000001", "http://0177.0.0.1", "http://127.0.0.1.", "http://[::1]",
    "http://[0:0:0:0:0:0:0:1]", "http://[::ffff:127.0.0.1]", "http://[::ffff:7f00:1]", "http://[::]", "http://10.0.0.1",
    "http://172.16.5.5", "http://192.168.0.1", "http://3232235521", "http://169.254.169.254",
    "http://169.254.169.254/latest/meta-data/", "http://2852039166", "http://0xa9fea9fe", "http://[fd00::1]",
    "http://[fe80::1]", "http://[64:ff9b::7f00:1]", "http://100.64.0.1", "http://224.0.0.1", "http://255.255.255.255",
    "http://127。0。0。1", "http://①②⑦.0.0.1", "https://[::ffff:169.254.169.254]/", "http://127.0.0.1:80",
    "http://localhost", "http://LOCALHOST", "http://localhost.", "http://foo.localhost", "http://app.local",
    "http://metadata.google.internal", "http://printer.lan", "http://db.corp", "http://router.home.arpa",
    "http://intranet", "http://singlelabel", "http://service.internal", "localhost:3000",
  ])("blocks %s", (u) => {
    const c = code(() => normalizeTargetUrl(u));
    expect(["non_public_ip", "internal_hostname", "invalid_url", "port_not_allowed"]).toContain(c);
  });
  it("uses the right code for common cases", () => {
    expect(code(() => normalizeTargetUrl("http://127.0.0.1"))).toBe("non_public_ip");
    expect(code(() => normalizeTargetUrl("http://localhost"))).toBe("internal_hostname");
    expect(code(() => normalizeTargetUrl("http://2130706433"))).toBe("non_public_ip");
  });
});

describe("validateRequestUrl (redirect targets)", () => {
  it("allows public https targets", () => {
    expect(validateRequestUrl("https://example.com/a?b=1").hostname).toBe("example.com");
  });
  it.each([
    "http://169.254.169.254/latest/meta-data", "http://10.0.0.5/admin", "https://localhost/", "ftp://example.com/",
    "http://example.com:8080/", "http://user:pw@example.com/", "not a url", "http://[::1]:80/",
  ])("blocks %s", (u) => expect(() => validateRequestUrl(u)).toThrow(SsrfError));
});
