import type { NextRequest } from "next/server";
import { getUser } from "@/lib/auth/next";
import { getDb } from "@/lib/cf";
import { newShareToken } from "@/lib/crypto";
import * as repo from "@/lib/db/repo";
import { env } from "@/lib/env";
import { json, sameOrigin, UUID } from "@/lib/http/guards";

type Ctx = { params: Promise<{ id: string }> };

/** Create a read-only share link. The token is shown exactly once; only its hash is stored. */
export async function POST(req: NextRequest, { params }: Ctx) {
  if (!sameOrigin(req)) return json({ error: "forbidden" }, 403);
  const { id } = await params;
  if (!UUID.test(id)) return json({ error: "not_found" }, 404);
  const user = await getUser();
  if (!user) return json({ error: "unauthenticated" }, 401);
  const db = await getDb();
  const scan = await repo.getScan(db, user.id, id); // ownership
  if (!scan) return json({ error: "not_found" }, 404);
  if (scan.status !== "completed") return json({ error: "not_ready", message: "Only completed reports can be shared." }, 409);

  const { token, hash } = await newShareToken();
  await repo.createShare(db, { scanId: id, userId: user.id, tokenHash: hash, expiresAt: scan.expires_at });
  await repo.recordEvent(db, { type: "share_created", scanId: id, userId: user.id });
  return json({ url: `${env.siteUrl}/r/${token}` }, 201);
}

/** Revoke every share link for this report. */
export async function DELETE(req: NextRequest, { params }: Ctx) {
  if (!sameOrigin(req)) return json({ error: "forbidden" }, 403);
  const { id } = await params;
  if (!UUID.test(id)) return json({ error: "not_found" }, 404);
  const user = await getUser();
  if (!user) return json({ error: "unauthenticated" }, 401);
  const db = await getDb();
  await repo.revokeShares(db, user.id, id);
  await repo.recordEvent(db, { type: "share_revoked", scanId: id, userId: user.id });
  return json({ ok: true });
}
