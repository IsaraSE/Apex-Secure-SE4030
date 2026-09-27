// [SECURITY][V5] VULNERABLE: next 16.2.2 has critical RCE, SSRF and middleware-bypass issues. A06:2021

import type { NextConfig } from "next";

const apiProxyTargetFromEnv = process.env.API_PROXY_TARGET || process.env.NEXT_PUBLIC_API_PROXY_TARGET;

let normalizedApiProxyTarget = "";

if (apiProxyTargetFromEnv) {
  normalizedApiProxyTarget = apiProxyTargetFromEnv.replace(/\/$/, "");
} else if (process.env.NODE_ENV === "development") {
  normalizedApiProxyTarget = "http://localhost:5000";
}

let apiProxyDestination = "";

if (normalizedApiProxyTarget) {
  if (normalizedApiProxyTarget.endsWith("/api")) {
    apiProxyDestination = `${normalizedApiProxyTarget}/:path*`;
  } else {
    apiProxyDestination = `${normalizedApiProxyTarget}/api/:path*`;
  }
}

const nextConfig: NextConfig = {
  // Vulnerability 7 (OWASP A05:2021 - Security Misconfiguration, DAST/ZAP):
  // ZAP flagged this Next.js client (http://localhost:3000) for missing
  // security headers (CSP, HSTS, X-Content-Type-Options, X-Frame-Options).
  // `poweredByHeader: false` stops the `X-Powered-By: Next.js` info leak, and
  // `headers()` below mirrors the header set the server already sends via
  // helmet() (see server/src/app.ts).
  poweredByHeader: false,
  async headers() {
    return [
      {
        source: "/:path*",
        headers: [
          {
            key: "Content-Security-Policy",
            value:
              "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; img-src 'self' data: https:; font-src 'self' data:; connect-src 'self' http://localhost:5000; object-src 'none'; frame-ancestors 'self'; base-uri 'self'; form-action 'self'",
          },
          {
            key: "Strict-Transport-Security",
            value: "max-age=31536000; includeSubDomains",
          },
          {
            key: "X-Content-Type-Options",
            value: "nosniff",
          },
          {
            key: "X-Frame-Options",
            value: "SAMEORIGIN",
          },
          {
            key: "Referrer-Policy",
            value: "no-referrer",
          },
          {
            key: "X-XSS-Protection",
            value: "0",
          },
        ],
      },
    ];
  },
  async rewrites() {
    if (!apiProxyDestination) {
      return [];
    }

    return [
      {
        source: "/api/:path*",
        destination: apiProxyDestination,
      },
    ];
  },
};

export default nextConfig;
