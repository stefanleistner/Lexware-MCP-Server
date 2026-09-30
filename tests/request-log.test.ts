import { describe, expect, it } from "vitest";
import * as jose from "jose";
import { describeVerifyError, peekToken, redactPath } from "../src/request-log.js";
import { createAccessTokenVerifier, requireAllowedEmailDomain } from "../src/oauth.js";

const SECRET_MARKER = "SUPERSECRETSIGNATURE";

async function makeToken(claims: jose.JWTPayload, key: CryptoKey | Uint8Array) {
  return new jose.SignJWT(claims).setProtectedHeader({ alg: "RS256", kid: "k1" }).sign(key);
}

describe("redactPath", () => {
  it("drops query strings and upload tickets", () => {
    expect(redactPath("/mcp?token=abc")).toBe("/mcp");
    expect(redactPath("/upload/tkt_123?x=1")).toBe("/upload/<ticket>");
    expect(redactPath("/status")).toBe("/status");
  });
});

describe("peekToken", () => {
  it("flags opaque tokens without echoing them", () => {
    const out = peekToken(SECRET_MARKER);
    expect(out.tokenFormat).toMatch(/opaque/);
    expect(JSON.stringify(out)).not.toContain(SECRET_MARKER);
  });
});

describe("token rejection logging", () => {
  const oauth = {
    issuer: "https://issuer.example",
    jwksUrl: "https://issuer.example/oauth2/jwks",
    resource: "https://srv.example/mcp",
    verifyAudience: true,
    allowedEmailDomains: [],
    userinfoUrl: "https://issuer.example/oauth2/userinfo",
    authorizationEndpoint: "",
    tokenEndpoint: "",
  };

  async function run(claims: jose.JWTPayload) {
    const { publicKey, privateKey } = await jose.generateKeyPair("RS256");
    const jwk = { ...(await jose.exportJWK(publicKey)), kid: "k1", alg: "RS256" };
    const jwks = jose.createLocalJWKSet({ keys: [jwk] });
    const events: Array<{ event: string; fields: Record<string, unknown> }> = [];
    const verify = createAccessTokenVerifier(oauth, {
      jwks: jwks as never,
      log: (event, fields = {}) => events.push({ event, fields }),
    });
    const token = await makeToken(claims, privateKey);
    await expect(verify(token)).rejects.toThrow();
    const logged = JSON.stringify(events);
    expect(logged).not.toContain(token);
    expect(logged).not.toContain(token.split(".")[2]);
    return events[0]!;
  }

  const now = Math.floor(Date.now() / 1000);
  it("names a wrong audience", async () => {
    const e = await run({ iss: oauth.issuer, aud: "https://other.example", sub: "u", exp: now + 60 });
    expect(e.event).toBe("auth.token_rejected");
    expect(e.fields.reason).toMatch(/wrong audience/);
    expect(e.fields.aud).toBe("https://other.example");
  });
  it("names a wrong issuer", async () => {
    const e = await run({ iss: "https://evil.example", aud: oauth.resource, sub: "u", exp: now + 60 });
    expect(e.fields.reason).toMatch(/wrong issuer/);
  });
  it("names an expired token", async () => {
    const e = await run({ iss: oauth.issuer, aud: oauth.resource, sub: "u", exp: now - 120 });
    expect(e.fields.reason).toBe("expired");
  });
});

describe("describeVerifyError", () => {
  it("recognises an unreachable JWKS", () => {
    const err = new TypeError("fetch failed", { cause: new Error("getaddrinfo ENOTFOUND") });
    expect(describeVerifyError(err).reason).toMatch(/JWKS not reachable/);
    expect(describeVerifyError(new jose.errors.JWKSTimeout()).reason).toMatch(/timeout/);
  });
});

describe("email domain refusal logging", () => {
  it("logs the domain only, not the address", () => {
    const events: Array<Record<string, unknown>> = [];
    const mw = requireAllowedEmailDomain(["asiastreetfood.com"], (_e, f = {}) => events.push(f));
    const req = { auth: { extra: { email: "someone@gmail.com" } } } as never;
    const res = { status: () => ({ json: () => undefined }) } as never;
    mw(req, res, () => undefined);
    expect(events[0]!.domain).toBe("gmail.com");
    expect(JSON.stringify(events)).not.toContain("someone");
  });
});
