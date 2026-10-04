/**
 * Scanner service. Runs INSIDE the Cloudflare Container (Node), reachable only through the Container
 * Durable Object binding from our Worker — it has no public route and holds no secrets or database access.
 *
 *   POST /scan  {"url": "..."}  →  NDJSON: {t:"stage"}… then {t:"report"} | {t:"refused"} | {t:"error"}
 *   GET  /ready →  200
 */
import http from "node:http";
import { runScan } from "../src/lib/scanner/engine";
import { ScanRefusedError } from "../src/lib/scanner/report";

const PORT = Number(process.env.PORT ?? 8080);
const MAX_CONCURRENT = Number(process.env.SCAN_CONCURRENCY ?? 3);
const HARD_TIMEOUT_MS = 100_000;
let active = 0;

const log = (event: string, f: Record<string, string | number | boolean> = {}) => console.log(JSON.stringify({ t: new Date().toISOString(), level: "info", event, ...f }));

export function createServer(scan: typeof runScan = runScan) {
  return http.createServer(async (req, res) => {
    if (req.method === "GET" && req.url === "/ready") return void res.writeHead(200).end("ok");
    if (req.method !== "POST" || req.url !== "/scan") return void res.writeHead(404).end();

    if (active >= MAX_CONCURRENT) return void res.writeHead(429, { "retry-after": "5" }).end();

    let body = "";
    for await (const chunk of req) {
      body += chunk;
      if (body.length > 4096) return void res.writeHead(413).end();
    }
    let url: unknown;
    try { url = (JSON.parse(body) as { url?: unknown }).url; } catch { /* handled below */ }
    if (typeof url !== "string" || url.length === 0 || url.length > 2048) return void res.writeHead(400).end();

    active++;
    res.writeHead(200, { "content-type": "application/x-ndjson", "cache-control": "no-store" });
    const send = (o: unknown) => res.write(JSON.stringify(o) + "\n");
    const killer = setTimeout(() => { send({ t: "error", message: "scan exceeded hard timeout" }); res.end(); }, HARD_TIMEOUT_MS);
    const started = Date.now();
    try {
      const report = await scan(url, { onStage: (stage) => void send({ t: "stage", stage }) });
      send({ t: "report", report });
      log("scan_done", { ms: Date.now() - started, requests: report.stats.requests });
    } catch (e) {
      if (e instanceof ScanRefusedError) {
        send({ t: "refused", code: e.code, message: e.message, detail: e.detail });
        log("scan_refused", { code: e.code });
      } else {
        send({ t: "error", message: "internal scanner error" }); // never forward error text: it may contain target data
        log("scan_error", { name: (e as Error).name });
      }
    } finally {
      clearTimeout(killer);
      active--;
      res.end();
    }
  });
}

if (process.env.VIBESEC_NO_LISTEN !== "1") {
  createServer().listen(PORT, "0.0.0.0", () => log("scanner_listening", { port: PORT }));
}
