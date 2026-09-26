# V5 – Vulnerable and Outdated Components (OWASP A06:2021)

**Owner:** Juthmini (IT22124708)
**Tool used:** `npm audit` (Software Composition Analysis)
**Raw scan output:** `audit-logs/npm-audit-server.txt`, `audit-logs/npm-audit-client.txt`

## Summary (before fix)

| Project | Critical | High | Moderate | Low | Total |
|---------|----------|------|----------|-----|-------|
| server  |    1     |   9  |    4     |  2  |  16   |
| client  |    1     |   8  |    3     |  2  |  14   |

## Key vulnerable packages – server (`server/package-lock.json`)

| Package | Vulnerable version | Severity | Problem | Comes from |
|---------|-------------------|----------|---------|------------|
| tar | <=7.5.20 | Critical | File smuggling, DoS | transitive |
| undici | <=6.27.0 | High | HTTP request smuggling, CRLF injection | @vercel/node |
| path-to-regexp | 4.0.0 - 6.2.2 | High | ReDoS | @vercel/node |
| minimatch / brace-expansion | various | High | ReDoS / DoS | transitive |
| mongoose | 8.0.0 - 8.24.0 | Moderate | Prototype pollution in update casting | direct dependency |
| qs / body-parser | various | Moderate | DoS | express |
| ajv | 7.0.0 - 8.17.1 | Moderate | ReDoS | @vercel/node |

## Key vulnerable packages – client (`client/package-lock.json`)

| Package | Vulnerable version | Severity | Problem | Comes from |
|---------|-------------------|----------|---------|------------|
| next | 9.3.4 - 16.3.2 | Critical | RCE, SSRF, middleware bypass, XSS, DoS | direct dependency (16.2.2) |
| axios | 1.0.0 - 1.17.0 | High | SSRF, prototype-pollution gadgets, header injection | direct dependency |
| postcss | <=8.5.22 | High | XSS, arbitrary file read | next / direct |
| sharp | <=0.35.4-rc.0 | High | libvips / libheif CVEs | next |
| form-data, follow-redirects | various | High / Moderate | CRLF injection, header leak | axios |

## Code locations marked with `[SECURITY][V5]` comments
- `server/src/config/db.ts` – mongoose import
- `server/src/app.ts` – express import
- `server/api/index.ts` – @vercel/node import
- `client/src/lib/api.ts` – axios import
- `client/next.config.ts` – next import

> Note: `package.json` files cannot contain comments (JSON format), so the vulnerable
> versions are documented here instead.

## Planned fix
1. Run `npm audit fix` for non-breaking patches.
2. Upgrade direct dependencies (next, mongoose, express, @vercel/node, tsx).
3. Use npm `overrides` for transitive packages that cannot be upgraded directly.
4. Re-run `npm audit` and confirm 0 vulnerabilities.