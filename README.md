# VibeSec

Paste a URL, get a plain-English security audit. VibeSec runs **passive, non-destructive** checks (a handful of ordinary GET requests), scores the result 0–100, and shows exact fixes for each finding.

> The score is an *external configuration assessment*. It is not proof that a site is secure, and a low score is not proof that a site is compromised.

**Runs entirely on Cloudflare:** Workers (Next.js 16 via OpenNext) · D1 (SQLite) · Queues · Cron Triggers · Containers (the scanner) · optional Turnstile.

## Architecture

```
Browser ─► Worker (Next.js UI + API) ──► D1 (users, sessions, scans, findings, events, shares)
              │  POST /api/scans: normalize → SSRF checks → DoH preflight → atomic quota INSERT
              ▼
        Queue "vibesec-scans" ─► Worker queue() ─► claim scan in D1 (idempotent)
                                        │ POST /scan (NDJSON stream: stages, then report)
                                        ▼
                         Container "ScannerContainer" (Node: container/server.ts)
                         DNS pinning · TLS inspection · ≤28 requests/scan · egress deny-list
        Cron */2: re-send lost jobs, fail hung ones · Cron hourly: retention purge
```

Why a Container for the scanner? Workers `fetch` can't pin DNS answers, read the TLS certificate/protocol, or probe legacy TLS — all central to the SSRF defence and the TLS rules. The container runs the exact Node scanner code that the 400+ tests exercise. It has **no database access and no secrets**; it is reachable only through the Durable Object binding.

| Layer | Path |
|---|---|
| Web + API | `src/app`, `src/components` |
| Entry (fetch + queue + cron + container class) | `worker/index.ts` |
| Scanner service (Container) | `container/server.ts`, `container/Dockerfile` |
| SSRF defence | `src/lib/ssrf/` |
| Collector (all scan I/O) · Rules (pure) · Scoring | `src/lib/scanner/` |
| D1 schema · repository (ownership enforced here) | `migrations/`, `src/lib/db/` |
| Auth (scrypt, sessions, throttling, Turnstile) | `src/lib/auth/` |
| Jobs (create-scan, queue processing) | `src/lib/jobs/` |

The Worker bundle never imports `node:http/tls/dns` — `npm run typecheck` compiles `worker/` with Workers types only, so a stray Node import fails the build.

## Quick start (local)

```bash
npm install
npm run gen-keys                     # (see below) put the output in .dev.vars
cp .dev.vars.example .dev.vars
npm run db:migrate:local             # applies migrations/ to local D1
npm run preview                      # OpenNext build + wrangler dev (Worker, D1, Queue, cron, all local)
npm test                             # 427 tests
npm run scanner                      # optional: run the scanner service directly on :8080
```

`gen-keys` is a one-liner: it prints `DATA_ENCRYPTION_KEY` (32 random bytes, base64), `IP_HASH_SECRET` and `CRON_SECRET`.

Local note: `wrangler dev` runs the Container only if Docker is installed; otherwise use `wrangler dev --enable-containers=false` — the UI, auth, D1 and queue all work, and scans fail after 3 retries with a clean error (this exact path is how the retry logic was verified).

## Deploy

```bash
npx wrangler login
npx wrangler d1 create vibesec                       # paste database_id into wrangler.jsonc
npx wrangler queues create vibesec-scans
npx wrangler queues create vibesec-scans-dlq
npm run db:migrate                                   # remote D1
npx wrangler secret put DATA_ENCRYPTION_KEY          # also IP_HASH_SECRET, CRON_SECRET (and TURNSTILE_SECRET_KEY if used)
# set NEXT_PUBLIC_SITE_URL in wrangler.jsonc "vars"
npm run deploy                                       # OpenNext build + wrangler deploy (builds & pushes the container; needs Docker)
```

Requires a Workers **Paid** plan (Containers, Queues, and the CPU budget for password hashing). Optional Turnstile: create a widget, set `NEXT_PUBLIC_TURNSTILE_SITE_KEY` at build time and the `TURNSTILE_SECRET_KEY` secret.

Observability: Workers Logs are enabled (structured JSON, never response content). `GET /api/admin/metrics` (Bearer `CRON_SECRET`) returns queue depth, oldest-queued age, last-hour completed/failed/refused/blocked/rate-limited/auth-throttled counts, error rate and worker latency p50/p95. Failed jobs after 3 retries go to the `vibesec-scans-dlq` queue.

## Scanner safety (SSRF & abuse)

- Only `http`/`https`; ports 80/443 only; no credentials in URLs; query/fragment dropped before storage.
- IPv4/IPv6 parsed numerically — decimal, hex, octal, shortened (`127.1`), IPv4-mapped/NAT64/6to4/Teredo, trailing dots, full-width dots — then classified against loopback, RFC 1918, CGNAT, link-local/metadata, multicast, reserved, documentation and non-global-unicast ranges. Internal names rejected before DNS.
- **Two DNS checks:** the Worker does a DoH preflight (fail fast, no queue slot wasted); the container resolves again, requires **every** answer to be public (mixed answers refused) and **pins** the socket to those addresses — no second lookup, so DNS rebinding can't swap in a private IP.
- Every redirect hop is re-validated. Max 5 redirects. Per scan ≤ 28 requests, ≤ 8 MB, ≤ 60 s; per request byte cap and hard timeout; `Accept-Encoding: identity`.
- **Infrastructure layer:** the container class sets `deniedHosts` for private/loopback/metadata ranges. Cloudflare applies this to HTTP:80; for HTTPS:443 it would require `interceptHttps`, which replaces the server certificate with Cloudflare's CA and would break TLS inspection — so it is deliberately left off, and port 443 relies on the in-code validation + pinning above.
- Per account: concurrency, hourly and daily quotas; per IP-hash and **per target host** limits — enforced in a single atomic `INSERT … SELECT … WHERE` in D1 (concurrent requests can't slip past a limit; covered by a test). Repeated blocked targets (default 5/hour) suspend the account for 24 h.
- Identifies as `VibeSecBot/1.0`. No response bodies stored; secrets redacted at detection; cookie values stripped; raw header snapshots AES-256-GCM encrypted (Web Crypto); IPs stored only as an HMAC.

**Out of scope by design:** password guessing, auth bypass, injection/XSS payloads, fuzzing, port scanning, probing `/.env` or `/.git`. Advanced checks, if ever added, must require verified domain ownership first.

## Authentication & data isolation

D1 has **no row-level security**, so ownership is enforced in `src/lib/db/repo.ts`: every function that reads or mutates user data takes the acting `userId` in its `WHERE` clause (tests cover cross-user reads, deletes, share revocation and findings lookups). Public share links resolve through a token hash and never expose raw headers.

Auth is first-party: scrypt (N=2¹⁵, r=8, p=3), 256-bit random session tokens stored only as SHA-256 hashes, `HttpOnly; Secure; SameSite=Lax` cookie (`__Host-` prefixed in production), sliding 30-day expiry, identical error for unknown email vs wrong password (with a dummy hash to equalise timing), failed-login throttling per email and per IP, signup throttling per IP, optional Turnstile, same-origin (CSRF) checks on every mutating route. Passwords: 10–128 chars, common/identity-derived passwords rejected.

## Adding a rule

1. Write a `Rule` (`id`, `title`, `category`, `run(obs) → Finding[]`) in the matching `src/lib/scanner/rules/*.ts` and add it to that file's array.
2. Add tests (`rules.test.ts`; the hardened `baseline()` fixture must still produce zero failures).
3. Done — engine, scoring, persistence and UI need no changes.

Critical/High only when the evidence itself demonstrates the problem; heuristics use `confidence: medium|low` (which also reduces score impact) and never exceed Medium.

## Verified vs not verified

Verified here: 427 tests (SSRF, redirects, DNS rebinding, every rule, scoring, D1 repository on real SQLite including atomic limits, auth, job processing with the real engine, container NDJSON protocol), typecheck for both runtimes, OpenNext production build, `wrangler deploy --dry-run`, the **real scanner against `example.com`** (real TLS/DNS; its TLS 1.0/1.1 finding was cross-checked with `curl` and badssl.com), and the full Worker locally under `wrangler dev` (migrations on local D1, signup/login/session, CSRF rejection, throttling, ownership isolation, queue consumer with retry/backoff and terminal failure, metrics, browser sign-in).

**Not verified:** building/running the container image (no Docker on the dev machine) and therefore the Worker→Container call in a real deployment; the actual Cloudflare deploy; Turnstile; scans of third-party sites beyond `example.com`. Do a smoke scan of a site you own right after the first deploy.

## Known limitations

- Legacy TLS 1.0/1.1 detection reports only when a handshake succeeds (no false positives; may miss some weak servers).
- Secret detection is intentionally conservative (provider-specific formats only).
- Only the submitted page, ≤ 6 same-origin scripts, ≤ 3 source maps and one login-looking page are examined.
- No email verification or password reset yet (needs Cloudflare Email Service); Turnstile + signup throttling are the abuse controls for now.
- The app's own CSP allows `'unsafe-inline'` scripts for Next.js bootstrap; a nonce-based CSP would tighten it.
