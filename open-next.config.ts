import { defineCloudflareConfig } from "@opennextjs/cloudflare";

// No incremental cache: every data page is dynamic (per-user) and the static pages are prerendered at build time.
export default defineCloudflareConfig();
