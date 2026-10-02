# 0006. Do not implement OIDC Back-Channel Logout

**Status:** Accepted
**Date:** 2026-08-02

## Context

OIDC Back-Channel Logout ([OpenID Connect Back-Channel Logout 1.0](https://openid.net/specs/openid-connect-backchannel-1_0.html)) lets an identity provider terminate a relying party's sessions without the user agent being involved: the IdP sends a server-to-server `POST` (optionally carrying a logout `token` JWT) to a receiver endpoint registered in the provider's client configuration, and the relying party is expected to destroy the corresponding local session.

This middleware keeps **no server-side session state at all**. The entire session — tokens, claims, expiry — is serialized, encrypted, and stored in a single sealed client-side cookie (`src/session/cookieSessionStorage.go`, [ADR-0002](0002-sealed-oidc-state/)). That is a deliberate property, not an accident: it is what lets the Traefik plugin and `cmd/extauth-server` scale horizontally behind any gateway with no shared cache, and it is why the plugin needs no Redis to be correct.

A back-channel logout request is an HTTP `POST` from the IdP to *our* server. It carries a `sid`, a `sub`, or a logout `token` — none of which this middleware can act on. There is no map from subject or session ID to any session, because no such map exists: the session is inside the user's browser cookie, and an inbound `POST` has no access to any browser's cookie jar. Even a logout `token` carrying a session ID could not be matched, because the session identifier this plugin issues is not an IdP `sid` and is never registered with the provider.

Supporting this, the discovery document's `backchannel_logout_supported` flag is parsed into `oidc/types.go` but has no consumer; there is nothing to gate.

## Decision

**Back-Channel Logout is not implemented, and will not be added while session state is client-side only.**

The gateway endpoint that would have to handle the IdP's `POST` is Traefik's own router or `cmd/extauth-server`'s listener. Neither can reach another user's browser cookie, so a receiver handler could only be a no-op. Implementing one — registering `backchannel_logout_uri` with providers, accepting an unverifiable `sid`-shaped request, and answering `200 OK` — would advertise a capability the system does not have: an operator would reasonably believe IdP-initiated logout terminates local sessions when it does not. A truthful "not supported" is safer than a functional-looking no-op.

Making it work requires giving up the stateless property, which is a deliberate non-goal for now (see Alternatives).

### Consequence, stated explicitly

**IdP-initiated logout does not terminate local sessions.** Only user-initiated logout (navigating to the logout endpoint in a browser, which clears that browser's cookie) does. Concretely:

- A user disabled or removed at the IdP keeps a working session in every browser that still holds the cookie, until the session expires on its own or the cookie is cleared.
- An operator who disables an account at the IdP will see users continue to be let through.
- The access/refresh token in the cookie is not revoked, so any bearer of that cookie continues to authenticate until expiry.
- Session lifetime is the only bound on the exposure window. Operators who require prompt offboarding must rely on short session lifetimes, not on IdP push.

This is documented as a known gap, not hidden. `BackchannelLogoutSupported` is left parsed-but-unused rather than wired to a handler, so the discovery flag can never be mistaken for an implemented feature.

## Alternatives

Both make back-channel logout implementable, and both cost the stateless property. Neither is adopted today; revisiting means revisiting [ADR-0005](0005-standalone-ext-authz-service/)'s horizontal-scaling assumption too.

1. **Server-side session store** — keep the cookie as an opaque session ID and move session contents to Redis (or an equivalent). The IdP's `POST` can then look up the session by `sid` and delete it, making back-channel logout fully implementable. Costs: a new hard runtime dependency, shared state between replicas, and session loss if the store is unavailable — which must then fail in a decision about whether to allow or deny. Also opens the `sid` correlation problem (registering IdP `sid` values, or mapping on `sub`, which is coarser and would kill every session for that user at once).
2. **Revocation-check on every request** — keep the cookie self-contained, but call the IdP's `RevocationEndpoint` (or introspect the token) on each request and reject if the token was revoked. This catches offboarding without a session store and without `sid` correlation, at the cost of a synchronous IdP round-trip on the hot path per request — unusable at scale without caching, and a caching scheme reintroduces most of the staleness back-channel logout was meant to avoid. This is a partial mitigation for the offboarding gap above, not a substitute for back-channel logout.

A third option, **periodic re-validation on session refresh** (re-check the ID token only when the session's tokens are renewed rather than on every request), is a cheaper version of (2) that shrinks the exposure window without any new infrastructure. It does not implement back-channel logout, but it is the proportionate first step if offboarding latency needs improving.

## Related

- [ADR-0001](0001-pkce-verifier-in-oidc-state/) — store PKCE `code_verifier` in OIDC `state`
- [ADR-0002](0002-sealed-oidc-state/) — seal entire OIDC `state`
- [ADR-0003](0003-login-csrf-binding/) — login CSRF cookie binding
- [ADR-0004](0004-oidc-nonce/) — OIDC `nonce` for ID tokens
- [ADR-0005](0005-standalone-ext-authz-service/) — standalone ext_authz service (`cmd/extauth-server`)