import type { NextFunction, Request, RequestHandler, Response } from "express";
import * as jose from "jose";

/**
 * Diagnostic logging for the HTTP layer and the OAuth gate.
 *
 * Hard rule for everything in this file: NEVER log a credential. No bearer token, no
 * part of one, no hash of one, no upload ticket, no query string (which may carry either).
 * What IS logged is metadata about a request or a token that is safe to publish: method,
 * path, status, user agent, whether an Authorization header was present, and — for a
 * token that failed verification — the claims a server operator needs to compare against
 * config (`iss`, `aud`, `exp`, header `alg`/`kid`). Those claims are the same values the
 * server advertises publicly in its own metadata documents; `sub` and `email` are not
 * logged (an email-domain refusal logs the domain only).
 */

export type LogFields = Record<string, string | number | boolean | undefined | string[]>;

/** One line of JSON per event on stderr, prefixed so it is easy to grep in Render logs. */
export function logEvent(event: string, fields: LogFields = {}): void {
  console.error(`[lexware-mcp] ${JSON.stringify({ event, ...fields })}`);
}

/**
 * The request path with anything secret removed: the query string is dropped entirely,
 * and the upload ticket in `/upload/:ticket` (a bearer capability) is replaced.
 */
export function redactPath(originalUrl: string): string {
  const path = originalUrl.split("?")[0] ?? "";
  return path.replace(/^\/upload\/[^/]+/, "/upload/<ticket>");
}

/**
 * Express middleware logging one line per request once the response is finished:
 * method, path, status, duration, user agent and whether an Authorization header was
 * sent (true/false only — never its value). Mount it first so it also sees requests the
 * auth gate rejects.
 */
export function requestLogger(log: typeof logEvent = logEvent): RequestHandler {
  return (req: Request, res: Response, next: NextFunction) => {
    const start = process.hrtime.bigint();
    let logged = false;
    const done = (aborted: boolean) => {
      if (logged) return;
      logged = true;
      const header = req.headers.authorization;
      log("http", {
        method: req.method,
        path: redactPath(req.originalUrl ?? req.url),
        status: res.statusCode,
        ms: Math.round(Number(process.hrtime.bigint() - start) / 1e6),
        auth: typeof header === "string" && header.length > 0,
        authScheme: typeof header === "string" ? (header.split(" ")[0] ?? "").slice(0, 16) : undefined,
        ua: (req.headers["user-agent"] ?? "").slice(0, 200),
        ...(aborted ? { aborted: true } : {}),
      });
    };
    res.on("finish", () => done(false));
    res.on("close", () => done(!res.writableFinished));
    next();
  };
}

/** Safe-to-log facts about a token WITHOUT verifying it. Never throws, never returns the token. */
export function peekToken(token: string): LogFields {
  const parts = token.split(".");
  if (parts.length !== 3) {
    // WorkOS/AuthKit and most IdPs issue JWTs; an opaque token here means the client got a
    // token that was not minted for a resource server (typically: no Resource Indicator).
    return { tokenFormat: parts.length === 5 ? "jwe" : "opaque (not a JWT)", tokenLength: token.length };
  }
  const out: LogFields = { tokenFormat: "jwt" };
  try {
    const header = jose.decodeProtectedHeader(token);
    out.alg = header.alg;
    out.kid = header.kid;
  } catch {
    out.header = "undecodable";
  }
  try {
    const claims = jose.decodeJwt(token);
    out.iss = typeof claims.iss === "string" ? claims.iss : undefined;
    out.aud = Array.isArray(claims.aud) ? claims.aud : typeof claims.aud === "string" ? claims.aud : undefined;
    if (typeof claims.exp === "number") {
      out.exp = new Date(claims.exp * 1000).toISOString();
      out.expiredSecondsAgo = Math.max(0, Math.floor(Date.now() / 1000) - claims.exp);
    }
    out.hasEmailClaim = typeof claims.email === "string";
    out.scope = typeof claims.scope === "string" ? claims.scope : undefined;
  } catch {
    out.claims = "undecodable";
  }
  return out;
}

/**
 * Turn whatever `jose.jwtVerify` threw into a short, specific reason an operator can act
 * on. The message strings of jose errors carry no token material; the TypeError from a
 * failed JWKS fetch carries only the network cause.
 */
export function describeVerifyError(err: unknown): LogFields {
  if (err instanceof jose.errors.JWTExpired) {
    return { reason: "expired", detail: err.message };
  }
  if (err instanceof jose.errors.JWTClaimValidationFailed) {
    const reasons: Record<string, string> = {
      iss: "wrong issuer (iss does not match OAUTH_ISSUER)",
      aud: "wrong audience (aud does not match OAUTH_RESOURCE — check the Resource Indicator at the IdP)",
      nbf: "not yet valid (nbf in the future — clock skew?)",
      iat: "invalid iat",
      sub: "invalid sub",
    };
    return {
      reason: reasons[err.claim] ?? `claim "${err.claim}" failed validation`,
      claim: err.claim,
      detail: err.message,
    };
  }
  if (err instanceof jose.errors.JWKSTimeout) {
    return { reason: "JWKS not reachable (timeout)", detail: err.message };
  }
  if (err instanceof jose.errors.JWKSNoMatchingKey) {
    return {
      reason: "no matching signing key in JWKS (kid unknown — token from a different issuer/environment?)",
      detail: err.message,
    };
  }
  if (err instanceof jose.errors.JWKSInvalid) {
    return { reason: "JWKS response invalid", detail: err.message };
  }
  if (err instanceof jose.errors.JWSSignatureVerificationFailed) {
    return { reason: "signature verification failed", detail: err.message };
  }
  if (err instanceof jose.errors.JOSEAlgNotAllowed || err instanceof jose.errors.JOSENotSupported) {
    return { reason: "unsupported/disallowed algorithm", detail: err.message };
  }
  if (err instanceof jose.errors.JWSInvalid || err instanceof jose.errors.JWTInvalid) {
    return { reason: "malformed token (not a valid JWS/JWT)", detail: err.message };
  }
  if (err instanceof jose.errors.JOSEError) {
    if (/JSON Web Key Set HTTP response/i.test(err.message)) {
      return { reason: "JWKS not reachable (non-200 HTTP response — check OAUTH_JWKS_URL / issuer)", detail: err.message };
    }
    return { reason: `jose error ${err.code}`, detail: err.message };
  }
  if (err instanceof Error) {
    // A failed fetch of the JWKS surfaces as a TypeError("fetch failed") with a cause.
    const cause = (err as Error & { cause?: unknown }).cause;
    const causeMsg = cause instanceof Error ? `${cause.name}: ${cause.message}` : undefined;
    const isFetch = err.name === "TypeError" && /fetch/i.test(err.message);
    return {
      reason: isFetch ? "JWKS not reachable (network error)" : `unexpected ${err.name}`,
      detail: err.message,
      ...(causeMsg ? { cause: causeMsg } : {}),
    };
  }
  return { reason: "unknown error", detail: String(err) };
}
