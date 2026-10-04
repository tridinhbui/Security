import { describe, expect, it } from "vitest";
import { fingerprint } from "../fingerprint";
import { parseHtml } from "../parse";
import { detectPublicConfig, detectSecrets, redact } from "../secrets";

describe("parseHtml", () => {
  const html = `<html><head><title> T </title><meta name="generator" content="WordPress 6"><meta http-equiv="refresh" content="5;url=https://x.org">
  <script src="/a.js" integrity="sha384-x" crossorigin="anonymous"></script><script src="//cdn.net/b.js"></script><script>var inline=1</script>
  <script type="application/ld+json">{"a":1}</script><link rel="stylesheet" href="https://cdn.net/c.css"></head>
  <body><img src="http://i.example.com/x.png"><iframe src="javascript:alert(1)"></iframe><a href="/login">l</a><a href="https://other.com/">o</a><a href="mailto:a@b.c">m</a>
  <form action="/go" method="POST"><input type="password"></form></body></html>`;
  const p = parseHtml(html, "https://example.com/dir/");
  it("resolves URLs and classifies scripts", () => {
    expect(p.title).toBe("T");
    const ext = p.scripts.filter((s) => !s.inline);
    expect(ext.map((s) => s.url)).toEqual(["https://example.com/a.js", "https://cdn.net/b.js"]);
    expect(ext[0]).toMatchObject({ sameOrigin: true, integrity: "sha384-x" });
    expect(ext[1]).toMatchObject({ sameOrigin: false });
    expect(p.scripts.filter((s) => s.inline)).toHaveLength(2);
  });
  it("ignores javascript:/mailto: and keeps same-origin anchors only", () => {
    expect(p.resources.some((r) => r.url.startsWith("javascript"))).toBe(false);
    expect(p.anchors).toEqual(["https://example.com/login"]);
  });
  it("extracts forms, meta tags and mixed-content candidates", () => {
    expect(p.forms[0]).toMatchObject({ action: "https://example.com/go", method: "post", hasPassword: true });
    expect(p.hasPasswordInput).toBe(true);
    expect(p.generator).toBe("WordPress 6");
    expect(p.metaRefresh).toContain("x.org");
    expect(p.resources.filter((r) => r.url.startsWith("http://")).map((r) => r.tag)).toEqual(["img"]);
  });
  it("never executes anything and tolerates garbage", () => {
    expect(() => parseHtml("<<<not html>>> <script", "https://example.com/")).not.toThrow();
    expect(parseHtml("", "https://example.com/").scripts).toEqual([]);
  });
});

describe("fingerprint", () => {
  it("detects platforms only from direct evidence", () => {
    expect(fingerprint({ server: "Vercel", "x-vercel-id": "x" }, "", null).platforms).toContain("vercel");
    expect(fingerprint({ server: "cloudflare", "cf-ray": "1" }, "", null).platforms).toContain("cloudflare");
    expect(fingerprint({ server: "nginx/1.25.3" }, "", null).platforms).toEqual(["nginx"]);
    expect(fingerprint({ server: "Apache/2.4.58 (Ubuntu)" }, "", null).platforms).toEqual(["apache"]);
    expect(fingerprint({ "x-powered-by": "Express" }, "", null).platforms).toEqual(["express"]);
    expect(fingerprint({}, '<script src="/_next/static/chunks/x.js">', null).platforms).toEqual(["nextjs"]);
  });
  it("reports nothing for an unknown stack (so no snippets are fabricated)", () => {
    expect(fingerprint({ server: "MyCustomServer" }, "<html>plain</html>", null).platforms).toEqual([]);
    expect(fingerprint({}, "", null).platforms).toEqual([]);
  });
  it("detects frontend technologies", () => {
    const t = fingerprint({}, '<link href="/wp-content/x.css"><script src="jquery-3.6.0.min.js"></script><div ng-version="17.0.0">', null).technologies;
    expect(t).toEqual(expect.arrayContaining(["WordPress", "jQuery", "Angular"]));
  });
});

describe("secrets helpers", () => {
  it("redact never returns the whole value", () => {
    const r = redact("sk_" + "live_" + "abcdefghijklmnopqrstuvwx") // built at runtime so secret scanners do not flag the fixture;
    expect(r).not.toContain("abcdefghij");
    expect(r).toContain("ký tự");
  });
  it("AKIA + 40-char secret pair is Critical; lone key id is Medium", () => {
    const secret = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYzZ9yXaB0cD";
    const pair = detectSecrets(`aws_key="${"AKI" + "A"}J3Q5R7T9V1X3Z5B7"; aws_secret="${secret}"`);
    expect(pair[0]).toMatchObject({ id: "aws-secret-pair", severity: "critical" });
    expect(detectSecrets(`id="${"AKI" + "A"}J3Q5R7T9V1X3Z5B7"`)[0]).toMatchObject({ id: "aws-access-key-id", severity: "medium" });
    expect(JSON.stringify(pair)).not.toContain(secret);
  });
  it("deduplicates repeated matches", () => {
    const k = "sk_live_" + "a1B2c3D4e5F6g7H8i9J0k1L2";
    expect(detectSecrets(`${k} ${k} ${k}`)).toHaveLength(1);
  });
  it("detectPublicConfig measures values but never returns them", () => {
    const out = detectPublicConfig(`{"NEXT_PUBLIC_SUPABASE_URL":"https://abc.supabase.co","VITE_PRIVATE_SECRET":'abcdefghijkl',"OTHER":"x"}`);
    expect(out.map((e) => e.key).sort()).toEqual(["NEXT_PUBLIC_SUPABASE_URL", "VITE_PRIVATE_SECRET"]);
    expect(out.find((e) => e.key === "VITE_PRIVATE_SECRET")!.sensitiveName).toBe(true);
    expect(JSON.stringify(out)).not.toContain("abcdefghijkl");
  });
});
