---
sidebar_position: 7
---

# Security Considerations

This page describes what this plugin can and cannot do, so that you can size your configuration against the risks you actually care about. Everything here follows from one design decision: **the plugin keeps no server-side session state.**

## Sessions are stateless

The entire session — tokens, claims, expiry, cached authorization result — is serialized, encrypted and stored in a single sealed cookie in the user's browser. Traefik holds nothing.

That is what makes the plugin scale horizontally behind any gateway with no Redis and no sticky sessions. It is also what produces every limit below.

### Logout does not terminate the session server-side

Navigating to [`logoutUri`](./middleware-configuration.md#plugin-config-block) clears the cookie **in that browser** and, when [`revokeTokensOnLogout`](./middleware-configuration.md#provider) is enabled and your IDP advertises a `revocation_endpoint`, revokes the refresh token at the IDP. There is no server-side record to destroy, so:

- Other browsers holding a copy of the same session cookie keep working.
- A cookie captured before logout keeps working on a device you cannot reach.
- The session is not "ended" anywhere except in the browser that performed the logout.

### A captured session cookie cannot be invalidated, only expired

There is no session registry to delete an entry from. The **only** way to invalidate an outstanding session cookie is to rotate [`secret`](./middleware-configuration.md#plugin-config-block) — which invalidates **every** session of **every** user at once, forcing a full re-login storm at the IDP.

Plan accordingly:

- Set [`maxSessionLifetimeSeconds`](./middleware-configuration.md#session-lifetime-bounds) to the shortest window that still matches your users' expectations. It is the only hard upper bound you have.
- Set [`sessionIdleTimeoutSeconds`](./middleware-configuration.md#session-lifetime-bounds) alongside it if you want abandoned sessions to die quickly.
- Keep [`revokeTokensOnLogout`](./middleware-configuration.md#provider) at its default `true`, so the refresh token dies with the browser that logs out, at least when your IDP supports revocation.

Two limits on the lifetime bounds, so you do not size them on a promise the code cannot keep:

- They only cover sessions in the **session cookie**. A request authenticated by an external `authorizationHeader` / `authorizationCookie` is a per-request pseudo-session and is neither bounded nor renewed.
- The **idle** bound is enforced against a durable timestamp that is refreshed at most once per quarter of the bound (capped at 60s) rather than on every request, so a session can exceed it by up to that one interval. The **total** lifetime bound is exact for any session sealed with a creation timestamp. A session ticket sealed *before* that timestamp existed carries none, so its bound is **backfilled from first use** — such a session gets the full `maxSessionLifetimeSeconds` measured from the first request that reaches this version, and the bound only starts being enforced against its true age once the ticket has been re-sealed. Treat the total bound as *eventually* exact rather than exact from the first request for any ticket predating the timestamp, and prefer a short `maxSessionLifetimeSeconds` if you need the tightest possible window during a rollout.

:::warning
If you need "disable this user right now, everywhere", this plugin cannot do it. Short session lifetimes plus IDP-side revocation of the user's sessions are the tools available to you.
:::

### IDP-initiated (back-channel) logout is not supported

The IDP cannot terminate your sessions. There is no back-channel logout endpoint, by design — see `docs/adr/0006-no-backchannel-logout.md` in the repository for the reasoning.

A back-channel logout is a server-to-server `POST` from the IDP to an endpoint on your gateway, carrying a `sid` or `sub`. The plugin has no map from those to a session, because the session is inside a browser cookie that an inbound `POST` cannot reach. Even a logout `token` carrying a session ID could not be matched: the identifier this plugin issues is not the IDP's `sid` and is never registered with the IDP. A handler that accepted such a request would have to be a no-op while appearing to work.

What this means in practice:

- A user disabled or removed at the IDP keeps a working session in every browser that still holds the cookie.
- Removing a group or role at the IDP does not revoke access already granted.
- Session lifetime bounds the exposure window. Choose it deliberately.

[Front-channel logout](https://openid.net/specs/openid-connect-frontchannel-1_0.html) *is* supported through `frontChannelLogoutUri` — the IDP loads a URL in the user's browser, which can then clear that browser's cookie. It reaches one browser, not all of them, and it requires the user to still have the IDP session.

A front-channel notification is only honoured when it carries a matching `iss` **and** either a matching `sid` or a matching `id_token_hint`. Accepting `iss` alone would make forced-logout CSRF trivial: `iss` is the same string for every user of the provider, so a single unauthenticated `GET` — an `<img>` tag on any page — would log any visitor out. A rejected notification returns `400` and leaves the cookie in place. See [Front-Channel Logout](./middleware-configuration.md#front-channel-logout).

### Claim changes at the IDP take effect only when the session is re-established

By default the claims in the session — and the authorization result computed from them — are evaluated **once, at login**. If a role is added or removed at the IDP afterwards, the running session keeps using the claims it was created with. This affects two things independently:

1. **Token claims.** The plugin refreshes the access/ID token automatically, but the IDP generally issues a new token from the *existing* SSO session, so group or role changes at the IDP are not reflected until the user re-authenticates.
2. **Authorization results.** [`authorization.assertClaims`](./middleware-configuration.md#authorization) is cached in the session unless [`checkOnEveryRequest`](./middleware-configuration.md#authorization) is `true`.

Set `checkOnEveryRequest: true` to re-evaluate `assertClaims` on every request. That bounds how stale an *authorization decision* can be to a single request, but it does **not** make the *claims* fresh — a changed claim still needs a re-login to arrive in the token. Note the cost: `checkOnEveryRequest` combined with [`useClaimsFromUserInfo`](./middleware-configuration.md#provider) adds an IDP round-trip to the hot path of every request.

:::tip
For offboarding latency, [`revokeTokensOnLogout`](./middleware-configuration.md#provider) plus a short [`maxSessionLifetimeSeconds`](./middleware-configuration.md#session-lifetime-bounds) is usually the right trade. Reach for `checkOnEveryRequest` when the risk is a *policy* change (who may reach this route), not an *identity* change (this user no longer exists).
:::

## Other boundaries worth knowing

- **Redirect URI wildcards are process-wide.** `TOA_ENABLE_REDIRECT_URI_WILDCARDS` must be set on the Traefik process; without it a `*` in an allowlist entry matches only that exact literal string. See [Redirect URI Wildcards](./middleware-configuration.md#redirect-uri-wildcards).
- **Forwarded headers are ignored unless you say otherwise.** With an empty `trustedProxies`, `X-Forwarded-Proto` / `X-Forwarded-Host` are not used when building absolute URLs or the `redirect_uri`. If Traefik is behind an ingress, list it — see [Trusted Proxies](./middleware-configuration.md#trusted-proxies).
- **The idle bound is per-process, and that is safe.** The "last used" timestamp is written back at most once per refresh interval *per replica*, tracked in an in-memory map that replicas do not share. With `N` replicas the refresh rate is roughly `N` times the documented one, so a session can overshoot [`sessionIdleTimeoutSeconds`](./middleware-configuration.md#session-lifetime-bounds) by *less* than the single-replica interval — the bound is tighter, never looser. Running many replicas does not weaken it.
- **There is no host allowlist.** The plugin has no option that restricts which `Host` values it will serve: with an empty `trustedProxies` the request's `Host` header is used **verbatim** to build an absolute callback URL. A router rule constraining which host reaches the middleware is the only host-level control, and behind an ingress the host the user sees is whatever that ingress forwards.
  This is a boundary, not a bypass: the callback URL built from an attacker-chosen host still has to be a **registered redirect URI at your IDP**. The IDP's registered-redirect-uri allowlist is the backstop that actually stops a hostile host from turning into an accepted callback, so keep it tight — exact entries, no wildcards — and keep it in sync with every host the plugin serves. Note also that `trustedProxies` is not a host filter either: it only decides whose `X-Forwarded-Host` may be believed.
- **Step-up needs `maxAuthAgeSeconds`.** `unauthorizedBehavior: Challenge` alone does not force a fresh authentication; an existing IDP session satisfies it silently. See [Step-Up Authentication](./middleware-configuration.md#step-up-authentication).
- **Spoofable *identity* headers are stripped; URL-reconstructing ones are not.** Before forwarding, the plugin unconditionally deletes the well-known identity headers a backend might mistake for proof of authentication — `X-Auth-Request-User` / `-Email` / `-Groups` / `-Preferred-Username`, `X-Forwarded-User` / `-Groups` / `-Email`, `Remote-User` / `Remote-Groups`, and the token-bearing `X-Auth-Request-Access-Token`, `X-Auth-Request-Token`, `X-Forwarded-Access-Token` — on every path (bypass, `Forward`, authenticated). On the authenticated path they are re-set from the verified session.
  It deliberately does **not** strip URL-reconstructing headers: `X-Forwarded-Uri`, `X-Original-Uri`, `X-Original-Url` and similar pass through. Those are routing inputs that legitimate gateways set in front of the middleware, and clearing them breaks deployments that rely on them. **A backend that re-derives routing, authorization, or tenancy from those headers must not trust them** — a client can send them directly to the backend on any path that bypasses this middleware, or on one where the middleware forwards the request unauthenticated. The mitigation is not in the plugin: restrict what can reach the backend with a `NetworkPolicy` or a gateway-level header allowlist that drops inbound `X-Forwarded-Uri` / `X-Original-*` before the backend sees them.
- **The IDP is on the request path.** [`oidcTimeoutSeconds`](./middleware-configuration.md#provider) bounds every outbound call so a hung IDP cannot pin your request handlers indefinitely.