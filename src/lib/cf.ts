import { getCloudflareContext } from "@opennextjs/cloudflare";
import type { D1Like } from "./db/d1";

/** Worker bindings used by the Next.js side of the app (types are declared structurally). */
export interface AppBindings {
  DB: D1Like;
  SCAN_QUEUE: { send(message: { scanId: string }): Promise<void> };
}

export async function bindings(): Promise<AppBindings> {
  const { env } = await getCloudflareContext({ async: true });
  return env as unknown as AppBindings;
}
export async function getDb(): Promise<D1Like> {
  return (await bindings()).DB;
}
