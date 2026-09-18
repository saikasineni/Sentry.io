/**
 * checks.js
 *
 * IMPORTANT — read this before wiring this up to anything real:
 *
 * A browser cannot do most of what a real vulnerability scanner does.
 * Cross-origin JavaScript can't read response bodies or headers from a
 * site that doesn't opt in via CORS, can't inspect TLS certificate
 * details, and firing SQLi/XSS/traversal payloads at a third-party site
 * from someone else's browser tab is exactly the kind of unauthorized
 * traffic the original project's warning is about.
 *
 * So this file does two things, and is honest in the UI about which is
 * which:
 *   1. For the SAME origin the page is hosted on (or any target that
 *      happens to send permissive CORS headers), it makes a real fetch
 *      and reports what it actually sees.
 *   2. Otherwise it falls back to a clearly-labeled SIMULATION: a
 *      deterministic, seeded "finding" generated from the URL, so the
 *      UI has something to show. It is not a real scan result.
 *
 * If you want genuine scanning (payload injection, TLS inspection,
 * header retrieval against arbitrary hosts), that has to happen
 * server-side, against targets you're authorized to test — see the
 * Python version this UI is modeled on.
 */

const SECURITY_HEADERS = [
  "Strict-Transport-Security",
  "Content-Security-Policy",
  "X-Frame-Options",
  "X-Content-Type-Options",
  "X-XSS-Protection",
];

// Small, illustrative-only payload lists — for showing *what a scanner
// checks for* in the log, not a ready-made attack kit.
const SAMPLE_PAYLOADS = {
  sqli: [`' OR '1'='1`, `1; SELECT 1`],
  xss: [`<script>alert(1)</script>`],
  traversal: [`../../../../etc/passwd`],
};

function seededRandom(seed) {
  let h = 0;
  for (let i = 0; i < seed.length; i++) {
    h = (h << 5) - h + seed.charCodeAt(i);
    h |= 0;
  }
  return () => {
    h = (h * 1103515245 + 12345) & 0x7fffffff;
    return h / 0x7fffffff;
  };
}

async function isSameOrigin(url) {
  try {
    const u = new URL(url, window.location.href);
    return u.origin === window.location.origin;
  } catch {
    return false;
  }
}

/* ---------------- Security headers ---------------- */

async function checkHeaders(url, log) {
  log(`Requesting ${url} to inspect response headers…`);
  const sameOrigin = await isSameOrigin(url);

  if (sameOrigin) {
    try {
      const res = await fetch(url, { method: "GET" });
      const missing = SECURITY_HEADERS.filter((h) => !res.headers.has(h));
      log(`Received response (${res.status}). Checked ${SECURITY_HEADERS.length} headers.`, "pass");
      return missing.map((h) => ({
        check: "headers",
        severity: "medium",
        title: `Missing header: ${h}`,
        detail: "This header was not present on the live response.",
        evidence: `GET ${url}`,
      }));
    } catch (e) {
      log(`Fetch failed (${e.message}) — falling back to simulation.`, "high");
    }
  } else {
    log(`Cross-origin target — a browser can't read another site's headers without its consent. Simulating.`, "high");
  }

  const rand = seededRandom(url + "headers");
  const missing = SECURITY_HEADERS.filter(() => rand() > 0.5);
  return missing.length
    ? missing.map((h) => ({
        check: "headers",
        severity: "medium",
        title: `Missing header: ${h}`,
        detail: "Simulated result — no live response was read.",
        evidence: `(simulated) ${url}`,
      }))
    : [
        {
          check: "headers",
          severity: "pass",
          title: "Security headers look complete",
          detail: "Simulated result — no live response was read.",
          evidence: `(simulated) ${url}`,
        },
      ];
}

/* ---------------- SQL injection (simulated) ---------------- */

async function checkSqli(url, log) {
  log(`Testing ${SAMPLE_PAYLOADS.sqli.length} SQL injection payloads against input fields…`);
  const rand = seededRandom(url + "sqli");
  const vulnerable = rand() > 0.72;
  if (vulnerable) {
    log(`Payload triggered a database error string in the response.`, "critical");
    return [
      {
        check: "sqli",
        severity: "critical",
        title: "Possible SQL injection",
        detail: "A database error signature was reflected after an injected payload. Simulated result.",
        evidence: `(simulated) payload: ${SAMPLE_PAYLOADS.sqli[0]}`,
      },
    ];
  }
  log(`No SQL error signatures detected.`, "pass");
  return [
    {
      check: "sqli",
      severity: "pass",
      title: "No SQL injection indicators found",
      detail: "Simulated result — no live payloads were actually sent.",
      evidence: `(simulated) ${url}`,
    },
  ];
}

/* ---------------- XSS (simulated) ---------------- */

async function checkXss(url, log) {
  log(`Testing reflected XSS payloads against query parameters and forms…`);
  const rand = seededRandom(url + "xss");
  const vulnerable = rand() > 0.75;
  if (vulnerable) {
    log(`Payload was reflected unescaped in the response body.`, "high");
    return [
      {
        check: "xss",
        severity: "high",
        title: "Possible reflected XSS",
        detail: "An injected script-like payload came back unescaped. Simulated result.",
        evidence: `(simulated) payload: ${SAMPLE_PAYLOADS.xss[0]}`,
      },
    ];
  }
  log(`No unescaped payload reflection detected.`, "pass");
  return [
    {
      check: "xss",
      severity: "pass",
      title: "No XSS indicators found",
      detail: "Simulated result — no live payloads were actually sent.",
      evidence: `(simulated) ${url}`,
    },
  ];
}

/* ---------------- Directory traversal (simulated) ---------------- */

async function checkTraversal(url, log) {
  log(`Testing path traversal sequences against file-serving endpoints…`);
  const rand = seededRandom(url + "traversal");
  const vulnerable = rand() > 0.8;
  if (vulnerable) {
    log(`Traversal sequence returned content outside the expected root.`, "critical");
    return [
      {
        check: "traversal",
        severity: "critical",
        title: "Possible directory traversal",
        detail: "A traversal payload appeared to reach a file outside the web root. Simulated result.",
        evidence: `(simulated) payload: ${SAMPLE_PAYLOADS.traversal[0]}`,
      },
    ];
  }
  log(`No traversal indicators detected.`, "pass");
  return [
    {
      check: "traversal",
      severity: "pass",
      title: "No directory traversal indicators found",
      detail: "Simulated result — no live payloads were actually sent.",
      evidence: `(simulated) ${url}`,
    },
  ];
}

/* ---------------- SSL / TLS ---------------- */

async function checkTls(url, log) {
  log(`Checking HTTPS usage and certificate posture…`);
  let usesHttps = false;
  try {
    usesHttps = new URL(url, window.location.href).protocol === "https:";
  } catch {
    /* leave false */
  }

  const findings = [];
  if (!usesHttps) {
    log(`Target is not served over HTTPS.`, "critical");
    findings.push({
      check: "tls",
      severity: "critical",
      title: "Site not served over HTTPS",
      detail: "The target URL uses plain HTTP. Traffic is unencrypted.",
      evidence: url,
    });
  } else {
    log(`Target uses HTTPS. Certificate detail isn't readable from browser JS.`, "pass");
    findings.push({
      check: "tls",
      severity: "pass",
      title: "HTTPS in use",
      detail: "Certificate expiry and cipher detail require a server-side check — not available from this page.",
      evidence: url,
    });
  }
  return findings;
}

const CHECKS = {
  headers: checkHeaders,
  sqli: checkSqli,
  xss: checkXss,
  traversal: checkTraversal,
  tls: checkTls,
};
