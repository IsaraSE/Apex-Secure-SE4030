/**
 * [V2: FIX] - Secure Cryptographic Key Management (OWASP A02:2021).
 * Eliminates all insecure hardcoded fallback secret literals ("fallback_secret" / "fallback_refresh_secret").
 * Strictly enforces that JWT_SECRET and JWT_REFRESH_SECRET are provided via environment variables,
 * rejects well-known insecure default keys, and ensures fail-fast server termination if missing.
 */

const INSECURE_FALLBACK_SECRETS = new Set([
  "fallback_secret",
  "fallback_refresh_secret",
  "secret",
  "changeme",
  "password",
  "123456",
]);

export const getJwtSecret = (): string => {
  const secret = process.env.JWT_SECRET;
  if (!secret || secret.trim().length === 0) {
    throw new Error(
      "FATAL SECURITY ERROR: JWT_SECRET environment variable is missing. " +
      "The server refuses to start with missing or undefined cryptographic keys (OWASP A02:2021)."
    );
  }
  if (INSECURE_FALLBACK_SECRETS.has(secret.trim().toLowerCase())) {
    throw new Error(
      "FATAL SECURITY ERROR: Insecure or default JWT_SECRET detected. " +
      "You must provide a strong cryptographic key via environment variables (OWASP A02:2021)."
    );
  }
  return secret;
};

export const getJwtRefreshSecret = (): string => {
  const refreshSecret = process.env.JWT_REFRESH_SECRET;
  if (!refreshSecret || refreshSecret.trim().length === 0) {
    throw new Error(
      "FATAL SECURITY ERROR: JWT_REFRESH_SECRET environment variable is missing. " +
      "The server refuses to start with missing or undefined cryptographic keys (OWASP A02:2021)."
    );
  }
  if (INSECURE_FALLBACK_SECRETS.has(refreshSecret.trim().toLowerCase())) {
    throw new Error(
      "FATAL SECURITY ERROR: Insecure or default JWT_REFRESH_SECRET detected. " +
      "You must provide a strong cryptographic key via environment variables (OWASP A02:2021)."
    );
  }
  return refreshSecret;
};
