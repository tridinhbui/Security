/**
 * Configuration. Values come from Worker vars/secrets, exposed on process.env by the
 * `nodejs_compat` flag (and from .dev.vars locally). Never import this from client components.
 */
function required(name: string): string {
  const v = process.env[name];
  if (!v) throw new Error(`Missing required environment variable ${name}`);
  return v;
}

const int = (name: string, fallback: number) => {
  const n = Number(process.env[name]);
  return Number.isFinite(n) && n > 0 ? Math.floor(n) : fallback;
};

export const env = {
  get dataKey() { return required("DATA_ENCRYPTION_KEY"); },
  get ipHashSecret() { return required("IP_HASH_SECRET"); },
  /** Danh sách email quản trị (phân tách bằng dấu phẩy). Chỉ có hiệu lực khi tài khoản đã liên kết Google (email đã được Google xác minh). */
  get adminEmails(): string[] { return (process.env.ADMIN_EMAILS ?? "").split(",").map((e) => e.trim().toLowerCase()).filter(Boolean); },
  get cronSecret() { return required("CRON_SECRET"); },
  get siteUrl() { return process.env.NEXT_PUBLIC_SITE_URL ?? "http://localhost:3000"; },
  /** Optional Cloudflare Turnstile on signup/login. Enabled when both keys are set. */
  get turnstileSecret() { return process.env.TURNSTILE_SECRET_KEY || null; },
  /** Google OAuth: client ID là công khai; client secret là bí mật (chỉ ở Worker). Cả hai phải có thì mới bật. */
  get googleClientId() { return process.env.GOOGLE_CLIENT_ID || null; },
  get googleClientSecret() { return process.env.GOOGLE_CLIENT_SECRET || null; },
  get googleEnabled() { return !!(process.env.GOOGLE_CLIENT_ID && process.env.GOOGLE_CLIENT_SECRET); },
  get isProd() { return process.env.NODE_ENV === "production"; },
  limits: {
    get dailyQuota() { return int("SCAN_DAILY_QUOTA", 3); },
    get monthlyQuota() { return int("SCAN_MONTHLY_QUOTA", 30); },
    get globalDailyCap() { return int("SCAN_GLOBAL_DAILY_CAP", 600); },
    get hourlyLimit() { return int("SCAN_HOURLY_LIMIT", 2); },
    get maxConcurrentPerUser() { return int("SCAN_MAX_CONCURRENT_PER_USER", 1); },
    get ipHourlyLimit() { return int("SCAN_IP_HOURLY_LIMIT", 15); },
    get hostHourlyLimit() { return int("SCAN_HOST_HOURLY_LIMIT", 4); },
    get ssrfStrikeThreshold() { return int("ABUSE_SSRF_STRIKES", 5); },
    get loginFailsPerEmail() { return int("AUTH_LOGIN_FAILS_PER_EMAIL", 5); },
    get loginFailsPerIp() { return int("AUTH_LOGIN_FAILS_PER_IP", 20); },
    get oauthFailsPerIp() { return int("AUTH_OAUTH_FAILS_PER_IP", 20); },
    get signupsPerIpPerHour() { return int("AUTH_SIGNUPS_PER_IP_HOUR", 5); },
  },
};
