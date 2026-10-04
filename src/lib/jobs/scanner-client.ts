import type { ScanReport } from "../scanner/report";
import { ScanRefusedError } from "../scanner/report";

/** Transport-level failure talking to the scanner (container down/overloaded): the job should be retried. */
export class ScannerUnavailableError extends Error {
  constructor(message: string) { super(message); this.name = "ScannerUnavailableError"; }
}

export interface ScannerClient {
  /** Runs one scan. Throws ScanRefusedError for policy refusals, ScannerUnavailableError for infrastructure faults. */
  scan(url: string, onStage: (stage: string) => Promise<void>): Promise<ScanReport>;
}

const MAX_RESPONSE_BYTES = 8 * 1024 * 1024;

type Line = { t: "stage"; stage: string } | { t: "report"; report: ScanReport } | { t: "refused"; code: string; message: string; detail?: string } | { t: "error"; message: string };

/**
 * ScannerClient backed by the Cloudflare Container: POST /scan, response is NDJSON progress + final report.
 * `send` is a fetch-like function bound to a container stub (or, in tests, an in-process server).
 */
export function createNdjsonScanner(send: (req: Request) => Promise<Response>): ScannerClient {
  return {
    async scan(url, onStage) {
      let res: Response;
      try {
        res = await send(new Request("http://scanner/scan", { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify({ url }) }));
      } catch (e) {
        throw new ScannerUnavailableError(`scanner request failed: ${(e as Error).name}`);
      }
      if (res.status === 429 || res.status >= 500) throw new ScannerUnavailableError(`scanner returned ${res.status}`);
      if (!res.ok || !res.body) throw new ScannerUnavailableError(`scanner returned ${res.status}`);

      const reader = res.body.getReader();
      const dec = new TextDecoder();
      let buf = "", total = 0;
      let report: ScanReport | null = null;
      const handle = async (raw: string) => {
        if (!raw.trim()) return;
        let line: Line;
        try { line = JSON.parse(raw) as Line; } catch { throw new ScannerUnavailableError("malformed scanner output"); }
        if (line.t === "stage") await onStage(line.stage);
        else if (line.t === "report") report = line.report;
        else if (line.t === "refused") throw new ScanRefusedError(line.code, line.message, line.detail);
        else if (line.t === "error") throw new ScannerUnavailableError(line.message);
      };
      for (;;) {
        const { done, value } = await reader.read().catch(() => { throw new ScannerUnavailableError("scanner stream interrupted"); });
        if (value) {
          total += value.length;
          if (total > MAX_RESPONSE_BYTES) { await reader.cancel(); throw new ScannerUnavailableError("scanner response too large"); }
          buf += dec.decode(value, { stream: true });
          let nl: number;
          while ((nl = buf.indexOf("\n")) >= 0) { await handle(buf.slice(0, nl)); buf = buf.slice(nl + 1); }
        }
        if (done) break;
      }
      await handle(buf);
      if (!report) throw new ScannerUnavailableError("scanner ended without a report");
      return report;
    },
  };
}
