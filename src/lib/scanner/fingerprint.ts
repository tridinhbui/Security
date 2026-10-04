import { header } from "./util";
import type { Headers } from "../ssrf/types";
import type { ParsedHtml, Platform } from "./types";

export interface Fingerprint {
  platforms: Platform[];
  technologies: string[];
}

/**
 * Conservative stack detection from response headers and HTML markers. Platforms drive
 * which remediation snippets we show, so we only report one when the evidence is direct.
 */
export function fingerprint(headers: Headers | undefined, html: string, parsed: ParsedHtml | null): Fingerprint {
  const platforms = new Set<Platform>();
  const tech = new Set<string>();
  const server = (header(headers, "server") ?? "").toLowerCase();
  const powered = (header(headers, "x-powered-by") ?? "").toLowerCase();

  if (server.includes("vercel") || header(headers, "x-vercel-id")) platforms.add("vercel");
  if (server.includes("cloudflare") || header(headers, "cf-ray")) platforms.add("cloudflare");
  if (/^nginx/.test(server)) platforms.add("nginx");
  if (/apache/.test(server)) platforms.add("apache");
  if (powered.includes("express")) platforms.add("express");
  if (powered.includes("next.js") || header(headers, "x-nextjs-cache") || header(headers, "x-nextjs-prerender") ||
      html.includes("/_next/static/") || html.includes("__NEXT_DATA__") || html.includes("self.__next_f")) {
    platforms.add("nextjs");
  }

  const has = (s: string | RegExp) => (typeof s === "string" ? html.includes(s) : s.test(html));
  if (platforms.has("nextjs")) tech.add("Next.js");
  if (platforms.has("nextjs") || has("data-reactroot") || has(/react(-dom)?[.@/-][\w.-]*\.js/i)) tech.add("React");
  if (has("/_nuxt/") || has("__NUXT__")) tech.add("Nuxt");
  if (has(/\bng-version=/) ) tech.add("Angular");
  if (has("/_app/immutable/")) tech.add("SvelteKit");
  if (has("astro-island") || has("/_astro/")) tech.add("Astro");
  if (has("___gatsby")) tech.add("Gatsby");
  if (has("__remixContext")) tech.add("Remix");
  if (has("/wp-content/") || has("/wp-includes/") || /wordpress/i.test(parsed?.generator ?? "")) tech.add("WordPress");
  if (has("cdn.shopify.com")) tech.add("Shopify");
  if (has("static.wixstatic.com")) tech.add("Wix");
  if (has("static1.squarespace.com")) tech.add("Squarespace");
  if (has(/jquery[.-][\d.]*(min\.)?js/i)) tech.add("jQuery");
  if (has("supabase.co")) tech.add("Supabase");
  if (has("firebaseapp.com") || has("firebaseio.com")) tech.add("Firebase");
  if (parsed?.generator) tech.add(parsed.generator.slice(0, 60));

  if (platforms.has("vercel")) tech.add("Vercel");
  if (platforms.has("cloudflare")) tech.add("Cloudflare");
  if (platforms.has("nginx")) tech.add("Nginx");
  if (platforms.has("apache")) tech.add("Apache");
  if (platforms.has("express")) tech.add("Express");

  return { platforms: [...platforms], technologies: [...tech] };
}
