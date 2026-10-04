/**
 * Beginner mode: friendlier titles and a small glossary. Purely presentational —
 * detection logic never depends on this file, and unknown rules fall back to their own title.
 */
export const PLAIN_TITLES: Record<string, string> = {
  "tls.https-available": "Does the site have a working padlock (HTTPS)?",
  "tls.certificate-expiry": "Is the padlock certificate about to run out?",
  "tls.protocol-version": "Does the site refuse old, weak encryption?",
  "tls.http-to-https-redirect": "Are visitors sent to the secure version?",
  "tls.hsts": "Does the site force browsers to stay on HTTPS?",
  "tls.insecure-login-form": "Are password forms protected?",
  "headers.csp": "Does the site limit which code can run on its pages?",
  "headers.frame-protection": "Can other sites trick visitors into clicking hidden buttons?",
  "headers.x-content-type-options": "Do browsers stop guessing file types?",
  "headers.broken": "Are the safety settings written correctly?",
  "browser.mixed-content": "Does a secure page load anything insecurely?",
  "browser.third-party-integrity": "Are outside scripts checked for tampering?",
  "browser.cors": "Which other websites can read this site's data?",
  "cookies.flags": "Are login cookies locked down?",
  "cookies.cache-control-sensitive": "Are private pages kept out of caches?",
  "exposure.secrets": "Are any passwords or keys visible in the page code?",
  "exposure.public-config": "What settings are visible to everyone?",
  "exposure.source-maps": "Is the site's original source code downloadable?",
  "exposure.robots-txt": "What does the crawler guide reveal?",
  "exposure.sitemap-xml": "Is there a page list for search engines?",
  "exposure.security-txt": "Can researchers tell you about a problem?",
  "config.server-disclosure": "Does the server announce its software version?",
  "config.technology": "What is the site built with?",
  "config.suspicious-redirects": "Do visitors get sent somewhere unexpected?",
  "config.dns-email-security": "Can someone fake emails from this domain?",
  "config.auth-surface": "How does login work, as seen from outside?",
  "privacy.referrer-policy": "How much do other sites learn about where visitors came from?",
  "privacy.permissions-policy": "Are camera, microphone and location locked?",
  "privacy.third-party-origins": "Which other companies see your visitors?",
};

export const GLOSSARY: Record<string, string> = {
  HTTPS: "The padlock. It encrypts what travels between a visitor and your site so others can't read or change it.",
  TLS: "The encryption technology behind HTTPS.",
  HSTS: "A rule that tells browsers “only ever talk to this site securely”.",
  CSP: "A list of the places your pages are allowed to load code from. Anything else is blocked.",
  "Content-Security-Policy": "A list of the places your pages are allowed to load code from. Anything else is blocked.",
  XSS: "An attack where someone sneaks their own code into your page so it runs for your visitors.",
  CORS: "Rules about which other websites may read responses from your site in a visitor's browser.",
  CSRF: "An attack that tricks a logged-in visitor's browser into doing something on your site without them knowing.",
  clickjacking: "Hiding your page inside an invisible frame so visitors click buttons they can't see.",
  SRI: "A fingerprint that lets the browser reject a script if someone has tampered with it.",
  "Subresource Integrity": "A fingerprint that lets the browser reject a script if someone has tampered with it.",
  cookie: "A small note your site saves in the visitor's browser, often to remember they're logged in.",
  HttpOnly: "Stops page scripts from reading a cookie, so stolen scripts can't steal the login.",
  Secure: "Only sends the cookie over the padlocked (HTTPS) connection.",
  SameSite: "Stops other sites from making the browser send your cookie along.",
  "source map": "A file that turns scrambled production code back into your readable original code.",
  "source maps": "Files that turn scrambled production code back into your readable original code.",
  SPF: "A public list of which servers may send email for your domain.",
  DMARC: "A policy that tells email providers what to do with fake mail pretending to be you.",
  CAA: "A DNS note listing which companies may issue padlock certificates for your domain.",
  "mixed content": "A secure page that still loads some things over the insecure connection.",
  Referrer: "The “where did you come from” information browsers pass to the next site.",
  "Row Level Security": "Database rules that decide which rows each user may read or change.",
  "security.txt": "A small public file telling security researchers how to contact you.",
  nosniff: "Tells browsers to trust the declared file type instead of guessing.",
};

/** Glossary entries whose term appears in the given text. */
export function glossaryFor(...texts: string[]): { term: string; meaning: string }[] {
  const hay = texts.join(" \n ");
  const out: { term: string; meaning: string }[] = [];
  const seen = new Set<string>();
  for (const [term, meaning] of Object.entries(GLOSSARY)) {
    if (new RegExp(`(^|[^\\w])${term.replace(/[.*+?^${}()|[\]\\]/g, "\\$&")}([^\\w]|$)`, "i").test(hay) && !seen.has(meaning)) {
      seen.add(meaning);
      out.push({ term, meaning });
    }
  }
  return out.slice(0, 4);
}
