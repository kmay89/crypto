# Quantum Vault — Site Security Checklist

A comprehensive security audit checklist for the Quantum Vault application.
Adapted from the [SCQCS](https://github.com/kmay89/SCQCS) security template.

---

## HTTP Security Headers

- [x] `Content-Security-Policy` — Strict CSP in `_headers` (single source of truth)
  - `script-src 'self' https://esm.sh` — No `'unsafe-inline'` for scripts
  - `style-src 'self' 'unsafe-inline' https://fonts.googleapis.com` — Inline styles only (lower risk)
  - `frame-ancestors 'none'` — Blocks all framing (clickjacking prevention)
  - `upgrade-insecure-requests` — Auto-upgrade HTTP to HTTPS
- [x] `Strict-Transport-Security` — HSTS with `includeSubDomains` and `preload` (1 year)
- [x] `X-Frame-Options: DENY` — Legacy clickjacking protection
- [x] `X-Content-Type-Options: nosniff` — Prevents MIME-type sniffing
- [x] `Referrer-Policy: strict-origin-when-cross-origin` — Controls referrer leakage
- [x] `Permissions-Policy` — Disables camera, mic, geolocation, payment, USB, FLoC
- [x] `Cross-Origin-Opener-Policy: same-origin` — Isolates browsing context
- [x] `Cross-Origin-Embedder-Policy: credentialless` — Blocks credentialed cross-origin loads
- [x] `Cross-Origin-Resource-Policy: same-origin` — Prevents cross-origin resource reading
- [x] `X-XSS-Protection` deliberately omitted — CSP replaces it; legacy header can introduce vulnerabilities

---

## Secrets & Sensitive Data

- [ ] No API keys, tokens, or credentials in source code
- [ ] No `.env` files committed to repository
- [ ] No PII (personally identifiable information) in repository
- [ ] `.gitignore` excludes `.env`, `.env.local`, `*.pem`, `*.key`, `*.crt`

**Verification command:**
```bash
grep -rn "password\|secret\|api.key\|token\|credential\|private.key\|sk_live\|pk_live" \
  --include="*.js" --include="*.html" --include="*.json" .
```

---

## Code Hygiene

- [ ] No `console.log()` / `console.error()` in production JavaScript
- [ ] No `TODO` / `FIXME` / `HACK` comments in production code
- [ ] No `debugger` statements
- [ ] No `eval()` or `new Function()` — no dynamic code execution
- [ ] All external `<a>` links use `rel="noopener noreferrer"`
- [ ] No inline `<script>` blocks — all JS in external `main.js`
- [ ] CDN imports pinned to exact versions (not `@latest`)

---

## Cryptographic Implementation

- [ ] Uses `crypto.getRandomValues()` for all random generation (CSPRNG)
- [ ] AES-GCM nonces are unique per encryption (random 12-byte IV)
- [ ] HKDF uses random 32-byte salt per derivation
- [ ] HKDF uses domain separator string (`QuantumVault-v1-AES256GCM`)
- [ ] Key lengths validated before use (X-Wing PK: 1216 bytes, SK: 32 bytes)
- [ ] Plaintext integrity verified via SHA-256 hash after decryption
- [ ] Encryption format includes version identifier for forward compatibility
- [ ] No keys written to localStorage, cookies, or any persistent storage

---

## Privacy & Data Collection

- [ ] Zero cookies — confirm no `Set-Cookie` headers
- [ ] Zero analytics — no Google Analytics, no Plausible, no tracking pixels
- [ ] Zero data persistence — no localStorage, sessionStorage, or IndexedDB
- [ ] All cryptographic keys exist only in browser memory during session
- [ ] No data transmitted to any server (all operations are client-side)
- [ ] `humans.txt` documents the privacy stance

---

## Compliance Framework Alignment

### HIPAA (where applicable)
| Control | Implementation |
|---------|---------------|
| Audit Controls (§164.312(b)) | Client-side only; no audit trail needed |
| Access Controls (§164.312(a)(1)) | User-controlled key management |
| Integrity (§164.312(c)(1)) | AES-GCM authentication + SHA-256 hash verification |
| Transmission Security (§164.312(e)(1)) | HSTS + upgrade-insecure-requests enforces TLS |

### GDPR
| Principle | Implementation |
|-----------|---------------|
| Data Minimization | Zero data collection, zero server processing |
| Purpose Limitation | Encryption tool only; no secondary use |
| Accountability | Open-source, auditable code |
| Right to Erasure | Nothing to erase — no data stored |

### ISO 27001
| Control | Implementation |
|---------|---------------|
| A.10 Cryptography | NIST FIPS 203/204 algorithms, Web Crypto API |
| A.12 Operations Security | CSP, security headers, manual audit checklists |
| A.14 System Acquisition | Pinned dependency versions, single CDN source |

### SOC 2
| Criteria | Implementation |
|----------|---------------|
| Security | Defense-in-depth headers, CSP, HSTS |
| Availability | Static site architecture (CDN-friendly) |
| Confidentiality | Client-side encryption, zero server storage |
| Processing Integrity | Authenticated encryption (GCM), hash verification |
| Privacy | Zero data collection, documented in humans.txt |

---

## Publishing Readiness

- [ ] `security.txt` and `.well-known/security.txt` present with valid `Expires` date
- [ ] `robots.txt` allows search and AI crawlers
- [ ] `sitemap.xml` has correct canonical URLs
- [ ] `site.webmanifest` configured with correct app name and theme
- [ ] `llms.txt` documents project for AI systems
- [ ] `_headers` configured for hosting platform (Netlify/Cloudflare)
- [ ] `_redirects` configured for security.txt rewrite
- [ ] `404.html` exists with `noindex` meta tag
- [ ] Open Graph and Twitter Card meta tags present in `index.html`
- [ ] `<meta name="description">` is set
- [ ] Favicon files added (if applicable)

---

## Post-Deploy Validation Tools

| Tool | What it Checks | URL |
|------|---------------|-----|
| Security Headers | HTTP response headers grade | https://securityheaders.com |
| SSL Labs | TLS configuration and certificate | https://www.ssllabs.com/ssltest/ |
| CSP Evaluator | Content Security Policy strength | https://csp-evaluator.withgoogle.com |
| Rich Results | Structured data / JSON-LD | https://search.google.com/test/rich-results |
| Facebook Debug | Open Graph rendering | https://developers.facebook.com/tools/debug/ |
| Twitter Card | Twitter card rendering | https://cards-dev.twitter.com/validator |

---

## Legal Copy Guidelines

### Words to Avoid
These words create liability risk. Use qualified alternatives:

| Avoid | Use Instead |
|-------|-------------|
| "permanent" | "long-lived", "durable" |
| "immutable" | "tamper-evident", "integrity-protected" |
| "impossible" | "computationally infeasible" |
| "guarantee" | "designed to", "intended to" |
| "unbreakable" | "resistant to known attacks" |
| "100% secure" | "follows current best practices" |

### Required Disclaimers
- Cryptographic implementations should note they follow published standards
- Security claims should reference specific standards (FIPS 203, FIPS 204)
- Post-quantum claims should note "based on current mathematical understanding"
