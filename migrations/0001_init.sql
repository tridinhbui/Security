-- VibeSec D1 schema (SQLite). D1 has no row-level security, so EVERY query that returns user data
-- is scoped by user_id in src/lib/db/repo.ts (covered by tests/ownership). Timestamps are ISO-8601 UTC text.

CREATE TABLE users (
  id             TEXT PRIMARY KEY,
  email          TEXT NOT NULL UNIQUE,            -- stored lower-cased
  password_hash  TEXT NOT NULL,                   -- scrypt$N$r$p$salt$hash
  retention_days INTEGER NOT NULL DEFAULT 90 CHECK (retention_days IN (7, 30, 90, 365)),
  abuse_score    INTEGER NOT NULL DEFAULT 0,
  blocked_until  TEXT,
  created_at     TEXT NOT NULL
);

CREATE TABLE sessions (
  id          TEXT PRIMARY KEY,                   -- sha256(session token); the token lives only in the cookie
  user_id     TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  created_at  TEXT NOT NULL,
  expires_at  TEXT NOT NULL
);
CREATE INDEX sessions_user_idx ON sessions (user_id);
CREATE INDEX sessions_expiry_idx ON sessions (expires_at);

-- Failed-login / signup throttling. `key` is an HMAC (email or IP), never raw values.
CREATE TABLE auth_attempts (
  id     INTEGER PRIMARY KEY AUTOINCREMENT,
  kind   TEXT NOT NULL,                           -- login_fail_email | login_fail_ip | signup_ip
  key    TEXT NOT NULL,
  at     TEXT NOT NULL
);
CREATE INDEX auth_attempts_idx ON auth_attempts (kind, key, at);

CREATE TABLE scans (
  id              TEXT PRIMARY KEY,
  user_id         TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  input_url       TEXT NOT NULL,                  -- normalized (no query/fragment)
  normalized_url  TEXT NOT NULL,
  host            TEXT NOT NULL,
  status          TEXT NOT NULL DEFAULT 'queued' CHECK (status IN
                    ('queued','validating','scanning_transport','checking_headers','analyzing_client','generating_report','completed','failed')),
  error_code      TEXT,
  error_message   TEXT,
  score           INTEGER CHECK (score BETWEEN 0 AND 100),
  grade           TEXT CHECK (grade IN ('A','B','C','D','F')),
  category_scores TEXT,                           -- JSON
  severity_counts TEXT,                           -- JSON
  platforms       TEXT NOT NULL DEFAULT '[]',     -- JSON array
  request_count   INTEGER,
  ip_hash         TEXT,                           -- HMAC(ip); raw IPs are never stored
  attempts        INTEGER NOT NULL DEFAULT 0,
  locked_at       TEXT,
  created_at      TEXT NOT NULL,
  started_at      TEXT,
  completed_at    TEXT,
  expires_at      TEXT
);
CREATE INDEX scans_user_created_idx ON scans (user_id, created_at DESC);
CREATE INDEX scans_status_idx ON scans (status, created_at);
CREATE INDEX scans_host_created_idx ON scans (host, created_at);
CREATE INDEX scans_ip_created_idx ON scans (ip_hash, created_at);
CREATE INDEX scans_expiry_idx ON scans (expires_at);

CREATE TABLE scan_targets (
  id            TEXT PRIMARY KEY,
  scan_id       TEXT NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
  role          TEXT NOT NULL,
  url           TEXT NOT NULL,
  final_url     TEXT,
  status_code   INTEGER,
  tls           TEXT,                             -- JSON (no private data)
  headers_enc   TEXT,                             -- AES-256-GCM encrypted JSON of redacted response headers
  resolved_ips  TEXT,                             -- JSON array
  error_code    TEXT,
  duration_ms   INTEGER,
  created_at    TEXT NOT NULL
);
CREATE INDEX scan_targets_scan_idx ON scan_targets (scan_id);

CREATE TABLE findings (
  id            TEXT PRIMARY KEY,
  scan_id       TEXT NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
  rule_id       TEXT NOT NULL,
  fingerprint   TEXT NOT NULL,
  title         TEXT NOT NULL,
  category      TEXT NOT NULL,
  severity      TEXT NOT NULL CHECK (severity IN ('critical','high','medium','low','info')),
  confidence    TEXT NOT NULL CHECK (confidence IN ('high','medium','low')),
  status        TEXT NOT NULL CHECK (status IN ('fail','pass','info','unknown')),
  evidence      TEXT NOT NULL DEFAULT '[]',       -- JSON, already redacted by the scanner
  explanation   TEXT NOT NULL,
  summary       TEXT NOT NULL,
  technical     TEXT,
  remediation   TEXT NOT NULL DEFAULT '{}',       -- JSON
  affected_url  TEXT,
  refs          TEXT NOT NULL DEFAULT '[]'        -- JSON
);
CREATE INDEX findings_scan_idx ON findings (scan_id);

-- Audit log + observability stream. Never contains response bodies.
CREATE TABLE scan_events (
  id          INTEGER PRIMARY KEY AUTOINCREMENT,
  scan_id     TEXT REFERENCES scans(id) ON DELETE CASCADE,
  user_id     TEXT REFERENCES users(id) ON DELETE SET NULL,
  type        TEXT NOT NULL,
  level       TEXT NOT NULL DEFAULT 'info' CHECK (level IN ('debug','info','warn','error')),
  message     TEXT,
  meta        TEXT NOT NULL DEFAULT '{}',         -- JSON of small scalars
  created_at  TEXT NOT NULL
);
CREATE INDEX scan_events_scan_idx ON scan_events (scan_id, id);
CREATE INDEX scan_events_user_type_idx ON scan_events (user_id, type, created_at);
CREATE INDEX scan_events_type_idx ON scan_events (type, created_at);

CREATE TABLE report_shares (
  id          TEXT PRIMARY KEY,
  scan_id     TEXT NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
  created_by  TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  token_hash  TEXT NOT NULL UNIQUE,               -- sha256(token); the token itself is shown once
  created_at  TEXT NOT NULL,
  expires_at  TEXT,
  revoked_at  TEXT
);
CREATE INDEX report_shares_scan_idx ON report_shares (scan_id);
