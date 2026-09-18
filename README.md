# Sentry — Vulnerability Scanner (Frontend)

A static HTML/CSS/JS dashboard modeled on the original Python scanner's feature
list: SQL injection, XSS, directory traversal, SSL/TLS, and security-header
checks, with a live scan log and an exportable findings report.

## Running it

No build step, no server required for the basics:

```
open index.html
```

Or serve it locally (needed for the same-origin header check to work):

```
python -m http.server 8000
# then visit http://localhost:8000
```

## What's real vs. simulated — read this first

A browser genuinely cannot do most of what the Python version does. This is a
frontend-only deliverable, so it's upfront about the gap rather than faking it
silently:

| Check | In this UI |
|---|---|
| Security headers | **Real** if the target is same-origin (or sends permissive CORS headers). Otherwise simulated — a browser can't read another site's response headers without its consent. |
| SQL injection | **Simulated.** Firing injection payloads at arbitrary third-party sites from someone's browser tab is exactly the unauthorized-traffic problem the original project's warning calls out. Real payload testing belongs server-side, against targets you're authorized to test. |
| Cross-site scripting | **Simulated**, same reasoning. |
| Directory traversal | **Simulated**, same reasoning. |
| SSL / TLS | Checks whether the URL is `https://`, which is real. Certificate expiry, cipher suite, and protocol version aren't readable from browser JS — that needs a server-side TLS handshake. |

Every simulated finding is labeled `(simulated)` in its evidence line and in
the scan log, so nothing in the exported report is presented as a genuine
result.

## If you want real scanning behind this

Point it at an API instead of `js/checks.js`'s simulation branches: stand up
the original Python scanner (or similar) as a small backend service, expose
an endpoint like `POST /scan { url, checks }`, and have `app.js` call that
instead of `CHECKS[checkKey]()` directly. That keeps the actual scanning logic
server-side, where it has real network access and where you can enforce
authorization before any test traffic goes out.

## Structure

```
vuln-scanner-frontend/
├── index.html          # layout: sidebar form, log panel, findings panel
├── css/
│   └── styles.css
├── js/
│   ├── checks.js        # one function per check type
│   └── app.js            # form handling, scan loop, rendering, export
└── README.md
```

## Warning

For educational and authorized testing purposes only. Do not point the real
(server-side) version of this at a target you don't have explicit permission
to test — unauthorized testing may be illegal.
