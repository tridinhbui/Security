import * as cheerio from "cheerio";
import type { FormRef, ParsedHtml, ResourceRef, ScriptRef } from "./types";

const MAX_RESOURCES = 400;
const MAX_ANCHORS = 200;
const MAX_INLINE_SCRIPT = 300_000;

function abs(base: string, ref: string | undefined): string | null {
  if (!ref) return null;
  const r = ref.trim();
  if (!r || r.startsWith("#") || /^(data|blob|javascript|mailto|tel|about):/i.test(r)) return null;
  try {
    return new URL(r, base).href;
  } catch {
    return null;
  }
}

/** Lightweight static HTML analysis. Never executes scripts. */
export function parseHtml(html: string, baseUrl: string): ParsedHtml {
  const $ = cheerio.load(html);
  const origin = new URL(baseUrl).origin;
  const sameOrigin = (u: string) => {
    try {
      return new URL(u).origin === origin;
    } catch {
      return false;
    }
  };

  const scripts: ScriptRef[] = [];
  $("script").each((_, el) => {
    const src = $(el).attr("src");
    if (src) {
      const u = abs(baseUrl, src);
      if (u) {
        scripts.push({
          url: u,
          inline: false,
          sameOrigin: sameOrigin(u),
          integrity: $(el).attr("integrity"),
          crossorigin: $(el).attr("crossorigin"),
        });
      }
    } else {
      const type = ($(el).attr("type") ?? "").toLowerCase();
      if (type && !/javascript|module|json|^$/.test(type)) return;
      const content = $(el).html() ?? "";
      if (content.trim()) {
        scripts.push({ url: null, inline: true, sameOrigin: true, content: content.slice(0, MAX_INLINE_SCRIPT) });
      }
    }
  });

  const stylesheets: ParsedHtml["stylesheets"] = [];
  $('link[rel~="stylesheet" i]').each((_, el) => {
    const u = abs(baseUrl, $(el).attr("href"));
    if (u) stylesheets.push({ href: u, integrity: $(el).attr("integrity"), sameOrigin: sameOrigin(u) });
  });

  const resources: ResourceRef[] = [];
  const add = (tag: string, attr: string, v: string | undefined) => {
    const u = abs(baseUrl, v);
    if (u && resources.length < MAX_RESOURCES) resources.push({ tag, attr, url: u });
  };
  $("script[src]").each((_, e) => add("script", "src", $(e).attr("src")));
  $('link[rel~="stylesheet" i]').each((_, e) => add("link", "href", $(e).attr("href")));
  $("iframe[src], frame[src]").each((_, e) => add("iframe", "src", $(e).attr("src")));
  $("img[src], source[src], audio[src], video[src], track[src]").each((_, e) => add(e.tagName.toLowerCase(), "src", $(e).attr("src")));
  $("object[data]").each((_, e) => add("object", "data", $(e).attr("data")));
  $("embed[src]").each((_, e) => add("embed", "src", $(e).attr("src")));

  const forms: FormRef[] = [];
  $("form").each((_, el) => {
    const action = abs(baseUrl, $(el).attr("action")) ?? baseUrl;
    forms.push({
      action,
      method: ($(el).attr("method") ?? "get").toLowerCase(),
      hasPassword: $(el).find('input[type="password" i]').length > 0,
    });
  });

  const anchors: string[] = [];
  $("a[href]").each((_, el) => {
    const u = abs(baseUrl, $(el).attr("href"));
    if (u && sameOrigin(u) && anchors.length < MAX_ANCHORS) anchors.push(u);
  });

  const metaCsp = $('meta[http-equiv="Content-Security-Policy" i]').attr("content") ?? null;
  const metaRefresh = $('meta[http-equiv="refresh" i]').attr("content") ?? null;
  const generator = $('meta[name="generator" i]').attr("content") ?? null;
  const metaReferrer = $('meta[name="referrer" i]').attr("content") ?? null;

  return {
    title: ($("title").first().text() ?? "").trim().slice(0, 200),
    scripts,
    stylesheets,
    resources,
    forms,
    hasPasswordInput: $('input[type="password" i]').length > 0,
    metaCsp,
    metaRefresh,
    generator,
    metaReferrer,
    anchors,
  };
}
