import { headerFix, httpsRedirectFix, RECOMMENDED } from "../remediation";
import type { Finding, Observations, Rule } from "../types";
import { header, headerEvidence, makeFinding, MDN, pass } from "../util";

const CAT = "Transport Security" as const;

const CERT_LABELS: Record<string, string> = {
  CERT_HAS_EXPIRED: "the certificate has expired",
  DEPTH_ZERO_SELF_SIGNED_CERT: "the certificate is self-signed",
  SELF_SIGNED_CERT_IN_CHAIN: "the certificate chain contains a self-signed certificate",
  UNABLE_TO_VERIFY_LEAF_SIGNATURE: "the certificate chain is incomplete or untrusted",
  UNABLE_TO_GET_ISSUER_CERT_LOCALLY: "the certificate issuer is not trusted",
  ERR_TLS_CERT_ALTNAME_INVALID: "the certificate does not match this domain name",
  CERT_NOT_YET_VALID: "the certificate is not valid yet",
  CERT_REVOKED: "the certificate has been revoked",
};

/** Error codes that positively indicate "no working HTTPS" (as opposed to a flaky network). */
const NO_TLS_CODES = new Set(["ECONNREFUSED", "EPROTO", "ERR_SSL_WRONG_VERSION_NUMBER", "ERR_SSL_PROTOCOL_ERROR"]);

const httpsAvailable: Rule = {
  id: "tls.https-available",
  title: "HTTPS is available with a valid certificate",
  category: CAT,
  run(obs) {
    const h = obs.https;
    if (!h) return [];
    const url = h.requestedUrl;
    const refs = [MDN("Web/Security/Transport_Layer_Security", "MDN: Transport Layer Security")];

    if (h.certError) {
      const why = CERT_LABELS[h.certError.code] ?? "the certificate could not be verified";
      return [
        makeFinding({
          ruleId: this.id, title: "HTTPS certificate is not trusted", category: CAT, severity: "high", confidence: "high",
          status: "fail", affectedUrl: url, references: refs,
          summary: `Browsers will warn visitors before loading this site because ${why}.`,
          explanation: "Visitors see a full-page security warning, and most will leave. Attackers on the same network can also impersonate your site if people click through.",
          technical: `TLS verification failed with ${h.certError.code}.`,
          evidence: [`GET ${url} → TLS error ${h.certError.code}`, ...(h.tls?.subject ? [`Certificate subject: ${h.tls.subject}`] : []), ...(h.tls?.validTo ? [`Valid until: ${h.tls.validTo}`] : [])],
          remediation: {
            summary: "Install a valid, publicly trusted certificate that covers this exact hostname, including the full chain.",
            steps: ["Most hosts (Vercel, Netlify, Cloudflare) issue free certificates automatically — check the domain is correctly attached.", "On your own server use Let's Encrypt (certbot) and make sure the fullchain file is configured, not just the leaf certificate.", "Confirm the certificate lists this hostname in its Subject Alternative Names."],
            snippets: [],
          },
        }),
      ];
    }
    if (h.error) {
      if (NO_TLS_CODES.has(h.error.code)) {
        return [
          makeFinding({
            ruleId: this.id, title: "HTTPS is not available", category: CAT, severity: "high", confidence: "high", status: "fail",
            affectedUrl: url, references: refs,
            summary: "This site does not accept HTTPS connections.",
            explanation: "Without HTTPS everything your visitors send and receive — including passwords — can be read or changed by anyone on the network path.",
            technical: `Connection to port 443 failed: ${h.error.code}.`,
            evidence: [`GET ${url} → ${h.error.code}`],
            remediation: { summary: "Enable HTTPS on your host or CDN and obtain a free certificate (Let's Encrypt or your platform's automatic certificates).", snippets: [] },
          }),
        ];
      }
      return [
        makeFinding({
          ruleId: this.id, title: "Could not complete an HTTPS check", category: CAT, severity: "info", confidence: "low", status: "unknown",
          affectedUrl: url, summary: "We couldn't reliably connect over HTTPS during this scan, so transport checks are incomplete.",
          explanation: "This is usually a temporary network problem, rate limiting or a slow server. Try re-scanning.",
          evidence: [`GET ${url} → ${h.error.code}: ${h.error.message}`], remediation: null,
        }),
      ];
    }
    return [pass({ ruleId: this.id, title: this.title, category: CAT, affectedUrl: url, summary: "HTTPS works and the certificate is trusted.", explanation: "Visitors get an encrypted connection to the genuine site.", evidence: [`TLS: ${h.tls?.protocol ?? "?"}, issuer: ${h.tls?.issuer ?? "?"}`], references: refs })];
  },
};

const certExpiry: Rule = {
  id: "tls.certificate-expiry",
  title: "Certificate is not about to expire",
  category: CAT,
  run(obs) {
    const t = obs.https?.tls;
    if (!t || t.daysRemaining === undefined || obs.https?.certError) return [];
    const url = obs.https!.requestedUrl;
    const evidence = [`Valid until ${t.validTo} (${t.daysRemaining} days)`];
    if (t.daysRemaining < 0) return []; // reported as an untrusted certificate
    if (t.daysRemaining < 14) {
      return [makeFinding({
        ruleId: this.id, title: "Certificate expires very soon", category: CAT, severity: "medium", confidence: "high", status: "fail", affectedUrl: url,
        summary: `The HTTPS certificate expires in ${t.daysRemaining} day(s).`,
        explanation: "When it expires, every visitor will see a security warning until it is renewed.",
        evidence, remediation: { summary: "Renew the certificate now and check that automatic renewal (certbot timer, platform auto-renew) is working.", snippets: [] },
      })];
    }
    if (t.daysRemaining < 30) {
      return [makeFinding({
        ruleId: this.id, title: "Certificate expires within 30 days", category: CAT, severity: "low", confidence: "high", status: "fail", affectedUrl: url,
        summary: `The HTTPS certificate expires in ${t.daysRemaining} days.`, explanation: "Automatic renewals usually happen ~30 days before expiry. If this one hasn't renewed, renewal may be broken.",
        evidence, remediation: { summary: "Verify that automatic renewal is running.", snippets: [] },
      })];
    }
    return [pass({ ruleId: this.id, title: this.title, category: CAT, affectedUrl: url, summary: `The certificate is valid for another ${t.daysRemaining} days.`, explanation: "Plenty of time before renewal is needed.", evidence })];
  },
};

const tlsProtocol: Rule = {
  id: "tls.protocol-version",
  title: "Modern TLS versions only",
  category: CAT,
  run(obs) {
    const url = obs.https?.requestedUrl ?? null;
    const legacy = obs.legacyTls;
    const bad: string[] = [];
    if (legacy?.tls10) bad.push("TLS 1.0");
    if (legacy?.tls11) bad.push("TLS 1.1");
    const negotiated = obs.https?.tls?.protocol;
    if (negotiated === "TLSv1" || negotiated === "TLSv1.1") bad.push(negotiated.replace("TLSv", "TLS "));
    if (bad.length) {
      const uniq = [...new Set(bad)];
      return [makeFinding({
        ruleId: this.id, title: "Outdated TLS versions are accepted", category: CAT, severity: "medium", confidence: "high", status: "fail", affectedUrl: url,
        references: [MDN("Web/Security/Transport_Layer_Security", "MDN: TLS")],
        summary: `The server still accepts ${uniq.join(" and ")}, which are deprecated.`,
        explanation: "Old TLS versions have known weaknesses. Modern browsers no longer use them, so disabling them costs nothing and removes downgrade risk.",
        technical: `A handshake limited to ${uniq.join("/")} succeeded.`,
        evidence: uniq.map((v) => `${v} handshake succeeded`),
        remediation: { summary: "Allow only TLS 1.2 and TLS 1.3.", steps: ["Nginx: ssl_protocols TLSv1.2 TLSv1.3;", "Apache: SSLProtocol -all +TLSv1.2 +TLSv1.3", "Cloudflare: SSL/TLS → Edge Certificates → Minimum TLS Version = 1.2", "Managed platforms (Vercel, Netlify) already enforce this."], snippets: [] },
      })];
    }
    if (!negotiated) return [];
    return [pass({ ruleId: this.id, title: this.title, category: CAT, affectedUrl: url, summary: `Connection negotiated ${negotiated.replace("TLSv", "TLS ")}${legacy && legacy.tls10 === false && legacy.tls11 === false ? "; TLS 1.0/1.1 are refused." : "."}`, explanation: "Modern TLS protects visitors' traffic.", evidence: [`Negotiated: ${negotiated}`, `Cipher: ${obs.https?.tls?.cipher ?? "?"}`] })];
  },
};

const httpRedirect: Rule = {
  id: "tls.http-to-https-redirect",
  title: "HTTP redirects to HTTPS",
  category: CAT,
  run(obs) {
    const h = obs.http;
    if (!h) return [];
    const url = h.requestedUrl;
    const httpsOk = obs.https && !obs.https.error && obs.https.status !== null;
    if (h.error) {
      if (["ECONNREFUSED", "ETIMEDOUT"].includes(h.error.code)) {
        return [makeFinding({ ruleId: this.id, title: "Port 80 (HTTP) is closed", category: CAT, severity: "info", confidence: "medium", status: "info", affectedUrl: url,
          summary: "Plain HTTP isn't answered at all.", explanation: "That's fine if every link uses https://, but visitors typing the bare domain may see an error instead of being redirected.",
          evidence: [`GET ${url} → ${h.error.code}`], remediation: httpsRedirectFix(obs.platforms) })];
      }
      return [];
    }
    const finalIsHttps = h.finalUrl.startsWith("https://");
    if (finalIsHttps) {
      const first = h.chain[0];
      return [pass({ ruleId: this.id, title: this.title, category: CAT, affectedUrl: url, summary: "HTTP requests are redirected to HTTPS.", explanation: "Visitors who start on http:// are moved to the secure version.", evidence: [`${first?.status} ${url} → ${h.finalUrl}`] })];
    }
    if (!httpsOk) return []; // no working HTTPS → reported by tls.https-available
    return [makeFinding({
      ruleId: this.id, title: "HTTP is not redirected to HTTPS", category: CAT, severity: "medium", confidence: "high", status: "fail", affectedUrl: url,
      references: [MDN("Web/Security/Transport_Layer_Security", "MDN: TLS")],
      summary: "The site answers on plain http:// and does not send visitors to the https:// version.",
      explanation: "Anyone who arrives over HTTP — from an old link, or typing the bare domain — stays unencrypted and can be spied on or tampered with.",
      technical: `GET ${url} returned ${h.status} without redirecting to https.`,
      evidence: [`GET ${url} → ${h.status}`, headerEvidence(h.headers, "location")], remediation: httpsRedirectFix(obs.platforms),
    })];
  },
};

const hsts: Rule = {
  id: "tls.hsts",
  title: "HTTP Strict Transport Security (HSTS)",
  category: CAT,
  run(obs) {
    const h = obs.https;
    if (!h || h.error || h.status === null) return [];
    const url = h.finalUrl;
    const v = header(h.headers, "strict-transport-security");
    const refs = [MDN("Web/HTTP/Reference/Headers/Strict-Transport-Security", "MDN: Strict-Transport-Security")];
    if (!v) {
      return [makeFinding({
        ruleId: this.id, title: "HSTS header is missing", category: CAT, severity: "medium", confidence: "high", status: "fail", affectedUrl: url, references: refs,
        summary: "The site doesn't tell browsers to always use HTTPS.",
        explanation: "Without HSTS, a visitor's first request can still go over plain HTTP, where an attacker on the network can intercept it and strip the encryption.",
        technical: "No Strict-Transport-Security header on the HTTPS response.",
        evidence: [headerEvidence(h.headers, "strict-transport-security")],
        remediation: headerFix("Strict-Transport-Security", RECOMMENDED.hsts, obs.platforms),
      })];
    }
    const maxAge = /max-age\s*=\s*"?(\d+)"?/i.exec(v);
    const age = maxAge ? Number(maxAge[1]) : NaN;
    if (Number.isNaN(age) || age === 0) return []; // reported by headers.broken
    if (age < 15_552_000) {
      return [makeFinding({
        ruleId: this.id, title: "HSTS lifetime is short", category: CAT, severity: "low", confidence: "high", status: "fail", affectedUrl: url, references: refs,
        summary: `HSTS is set but only lasts ${Math.round(age / 86400)} days.`, explanation: "A short lifetime means browsers forget the HTTPS-only rule quickly, leaving returning visitors exposed.",
        evidence: [headerEvidence(h.headers, "strict-transport-security")], remediation: headerFix("Strict-Transport-Security", RECOMMENDED.hsts, obs.platforms, "Raise max-age to at least 6 months (ideally 2 years)."),
      })];
    }
    const notes = [!/includeSubDomains/i.test(v) ? "includeSubDomains is not set" : "", !/preload/i.test(v) ? "not preload-ready" : ""].filter(Boolean);
    return [pass({ ruleId: this.id, title: this.title, category: CAT, affectedUrl: url, summary: `HSTS is enabled for ${Math.round(age / 86400)} days${notes.length ? ` (${notes.join(", ")})` : ""}.`, explanation: "Browsers will refuse to use plain HTTP for this site.", evidence: [headerEvidence(h.headers, "strict-transport-security")], references: refs })];
  },
};

const insecureLogin: Rule = {
  id: "tls.insecure-login-form",
  title: "Login forms are protected by HTTPS",
  category: CAT,
  run(obs: Observations): Finding[] {
    const html = obs.html;
    if (!html || !obs.page) return [];
    const out: Finding[] = [];
    const pageUrl = obs.page.finalUrl;
    const pwForms = html.forms.filter((f) => f.hasPassword);

    for (const f of pwForms) {
      if (f.action.startsWith("http://")) {
        out.push(makeFinding({
          ruleId: this.id, title: "Password form submits over plain HTTP", category: CAT, severity: "critical", confidence: "high", status: "fail",
          affectedUrl: pageUrl, key: `action:${new URL(f.action).host}${new URL(f.action).pathname}`,
          summary: "A form with a password field sends its data to an http:// address.",
          explanation: "Passwords are transmitted unencrypted and can be read by anyone between the visitor and the server.",
          technical: `<form action="${f.action}"> contains input[type=password].`, evidence: [`form action: ${f.action}`, `page: ${pageUrl}`],
          remediation: { summary: "Serve the page and the form target over HTTPS only.", steps: ["Change the form's action to an https:// URL (or a relative path on an HTTPS page).", "Redirect all HTTP traffic to HTTPS and enable HSTS."], snippets: [] },
        }));
      }
      if (f.method === "get") {
        out.push(makeFinding({
          ruleId: this.id, title: "Password form uses GET", category: CAT, severity: "high", confidence: "high", status: "fail", affectedUrl: pageUrl, key: "method-get",
          summary: "A password form submits using the GET method.",
          explanation: "GET puts the password in the URL, where it ends up in browser history, server logs and referrer headers.",
          technical: `<form method="get"> contains input[type=password].`, evidence: [`form action: ${f.action}`, "method: get"],
          remediation: { summary: 'Use method="post" for any form that carries credentials.', snippets: [] },
        }));
      }
    }
    if (!obs.pageIsHttps && html.hasPasswordInput && !out.some((f) => f.title.includes("plain HTTP"))) {
      out.push(makeFinding({
        ruleId: this.id, title: "Password field served over plain HTTP", category: CAT, severity: "high", confidence: "high", status: "fail", affectedUrl: pageUrl, key: "page-http",
        summary: "A page with a password field is delivered over unencrypted HTTP.",
        explanation: "The page can be altered in transit (to steal passwords), and the submission itself is unencrypted.",
        evidence: [`page: ${pageUrl}`, "input[type=password] present"],
        remediation: httpsRedirectFix(obs.platforms),
      }));
    }
    if (out.length === 0 && pwForms.length > 0) {
      return [pass({ ruleId: this.id, title: this.title, category: CAT, affectedUrl: pageUrl, summary: "Password forms are served over HTTPS and submit via POST.", explanation: "Credentials are encrypted in transit.", evidence: [`${pwForms.length} password form(s) found`] })];
    }
    return out;
  },
};

export const transportRules: Rule[] = [httpsAvailable, certExpiry, tlsProtocol, httpRedirect, hsts, insecureLogin];
