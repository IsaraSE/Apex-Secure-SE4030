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
  // security headers (CSP, HSTS, X-Content-Type-Options, X-Frame-Options),
  // exposing it to clickjacking/XSS-adjacent attacks. No `headers()` function
  // is defined here, so none of these are currently sent. Add a `headers()`
  // callback (or middleware) returning these headers to remediate.
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
