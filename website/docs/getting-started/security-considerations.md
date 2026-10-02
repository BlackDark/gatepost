---
sidebar_position: 7
---

# Security Considerations

This page describes what this plugin can and cannot do, so that you can size your configuration against the risks you actually care about. Everything here follows from one design decision: **the plugin keeps no server-side session state.**

## Sessions are stateless

The entire session — tokens, claims, expiry, cached authorization result — is serialized, encrypted and stored in a single sealed cookie in the user's browser. Traefik holds nothing.

That is what makes the plugin scale horizontally behind any gateway with no Redis and no sticky sessions. It is also what produces every limit below.

### Logout does not terminate the session server-side

Navigating to [`logoutUri`](./middleware-configuration.md#plugin-config-block) clears the cookie **in that browser** and, when [`revoke_tokens_on_logout`](./middleware-configuration.md#provider) is enabled and your IDP advertises a `revocation_endpoint`, revokes the refresh token at the IDP. There is no server-side record to destroy, so:

- Other browsers holding a copy of the same session cookie keep working.
- A cookie captured before logout keeps working on a device you cannot reach.
- The session is not "ended" anywhere except in the browser that performed the logout.

### A captured session cookie cannot be invalidated, only expired

There is no session registry to delete an entry from. The **only** way to invalidate an outstanding session cookie is to rotate [`secret`](./middleware-configuration.md#plugin-config-block) — which invalidates **every** session of **every** user at once, forcing a full re-login storm at the IDP.

Plan accordingly:

- Set [`max_session_lifetime_seconds`](./middleware-configuration.md#session-lifetime-bounds) to the shortest window that still matches your users' expectations. It is the only hard upper bound you have.
- Set [`session_idle_timeout_seconds`](./middleware-configuration.md#session-lifetime-bounds) alongside it if you want abandoned sessions to die quickly.
- Keep [`revoke_tokens_on_logout`](./middleware-configuration.md#provider) at its default `true`, so the refresh token dies with the browser that logs out, at least when your IDP supports revocation.

Two limits on the lifetime bounds, so you do not size them on a promise the code cannot keep:

- They only cover sessions in the **session cookie**. A request authenticated by an external `authorizationHeader` / `authorizationCookie` is a per-request pseudo-session and is neither bounded nor renewed.
- The **idle** bound is enforced against a durable timestamp that is refreshed at most once per quarter of the bound (capped at 60s) rather than on every request, so a session can exceed it by up to that one interval. The **total** lifetime bound is exact.

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
For offboarding latency, [`revoke_tokens_on_logout`](./middleware-configuration.md#provider) plus a short [`max_session_lifetime_seconds`](./middleware-configuration.md#session-lifetime-bounds) is usually the right trade. Reach for `checkOnEveryRequest` when the risk is a *policy* change (who may reach this route), not an *identity* change (this user no longer exists).
:::

## Other boundaries worth knowing

- **Redirect URI wildcards are process-wide.** `TOA_ENABLE_REDIRECT_URI_WILDCARDS` must be set on the Traefik process; without it a `*` in an allowlist entry matches only that exact literal string. See [Redirect URI Wildcards](./middleware-configuration.md#redirect-uri-wildcards).
- **Forwarded headers are ignored unless you say otherwise.** With an empty `trusted_proxies`, `X-Forwarded-Proto` / `X-Forwarded-Host` are not used when building absolute URLs or the `redirect_uri`. If Traefik is behind an ingress, list it — see [Trusted Proxies](./middleware-configuration.md#trusted-proxies).
- **Step-up needs `max_auth_age_seconds`.** `unauthorizedBehavior: Challenge` alone does not force a fresh authentication; an existing IDP session satisfies it silently. See [Step-Up Authentication](./middleware-configuration.md#step-up-authentication).
- **The IDP is on the request path.** [`oidc_timeout_seconds`](./middleware-configuration.md#provider) bounds every outbound call so a hung IDP cannot pin your request handlers indefinitely.