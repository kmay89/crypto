# Quantum Vault — Pre-Deployment Checklist

Run these checks **before every deploy** to catch common issues.

---

## 1. Debug Code Removal

```bash
# Search for debug statements, TODOs, and placeholder text
grep -rn "console\.log\|console\.error\|console\.warn\|console\.debug" *.js *.html
grep -rn "TODO\|FIXME\|HACK\|XXX" *.js *.html *.md
grep -rn "debugger" *.js *.html
grep -rn "lorem ipsum\|placeholder" *.js *.html
```

**Expected:** Zero matches in production code.

---

## 2. Secrets & Credentials Scan

```bash
# Search entire repo for potential secrets
grep -rn "password\|secret\|api.key\|token\|credential\|private.key" --include="*.js" --include="*.html" --include="*.json"
grep -rn "sk_live\|pk_live\|Bearer " .
```

**Expected:** No real secrets. Only references to user-supplied keys in the UI.

---

## 3. Placeholder Domain Check

```bash
# Ensure no placeholder or dev domains remain
grep -rn "example\.com\|localhost\|127\.0\.0\.1\|0\.0\.0\.0" *.html *.js *.txt *.xml
```

**Expected:** Zero matches (update sitemap.xml and security.txt with real domain before deploy).

---

## 4. Required Files Exist

```bash
# Verify all security and publishing files are present
for f in index.html main.js _headers _redirects .gitignore \
         security.txt .well-known/security.txt robots.txt \
         humans.txt llms.txt sitemap.xml site.webmanifest \
         404.html LICENSE CONTRIBUTING.md; do
  [ -f "$f" ] && echo "OK: $f" || echo "MISSING: $f"
done
```

---

## 5. Content Security Policy Verification

```bash
# Verify CSP is defined in _headers and NOT in HTML meta tags
grep -n "Content-Security-Policy" _headers
grep -n "Content-Security-Policy" index.html
```

**Expected:** CSP found in `_headers` only. Not in `index.html`.

---

## 6. External Links Audit

```bash
# Check all external links have rel="noopener noreferrer" (for <a> tags)
grep -n 'href="http' index.html 404.html
```

**Expected:** All `<a>` tags with external URLs include `rel="noopener noreferrer"`.

---

## 7. security.txt Validity

- [ ] `Expires` date is in the future
- [ ] `Contact` URL is valid and reachable
- [ ] `Canonical` URL matches your deployed domain
- [ ] Root `/security.txt` rewrites to `/.well-known/security.txt` via `_redirects`

---

## 8. Inline Script Check

```bash
# Ensure no inline <script> blocks (CSP requires external scripts)
grep -n "<script" index.html 404.html
```

**Expected:** Only `<script type="module" src="main.js">` — no inline script content.

---

## 9. CDN Dependency Check

```bash
# Verify external CDN imports are pinned to exact versions
grep -n "esm.sh" main.js
```

**Expected:** All imports pinned to exact version (`@0.5.2`), not `@latest` or ranges.

---

## 10. Post-Deploy Verification

After deploying, test with these external tools:

| Tool | URL |
|------|-----|
| Security Headers | https://securityheaders.com |
| SSL Labs | https://www.ssllabs.com/ssltest/ |
| CSP Evaluator | https://csp-evaluator.withgoogle.com |
| Rich Results | https://search.google.com/test/rich-results |
| Facebook Debug | https://developers.facebook.com/tools/debug/ |
| Twitter Card | https://cards-dev.twitter.com/validator |

---

## Quick One-Liner

Run all grep checks at once:

```bash
echo "=== Debug ===" && \
grep -rn "console\.\|TODO\|FIXME\|debugger" *.js *.html 2>/dev/null; \
echo "=== Secrets ===" && \
grep -rn "password\|api.key\|token\|credential" --include="*.js" --include="*.html" 2>/dev/null; \
echo "=== Placeholders ===" && \
grep -rn "example\.com\|localhost" *.html *.js *.txt *.xml 2>/dev/null; \
echo "=== Done ==="
```
