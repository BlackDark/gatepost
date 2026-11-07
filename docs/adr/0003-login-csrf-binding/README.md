# 0003. Login CSRF cookie binding

**Status:** Accepted  
**Date:** 2026-07-19  
**Related:** [ADR 0002](../0002-sealed-oidc-state/), `docs/tasks.md` Task 2

## Context

Sealed state (ADR 0002) stops tampering without `Secret`. It does not stop classic **login CSRF**: attacker starts an authorize flow (gets a valid sealed `state` for their account), then tricks the victim's browser into hitting the callback with that `state` + code, logging the victim into the attacker's session.

## Decision

On every authorize redirect that produces a Login (or RedirectThenLogin → Login) flow:

1. Generate a high-entropy random `csrf` value.
2. Store it in sealed `OidcState.Csrf`.
3. Set HttpOnly Secure cookie `CookieNamePrefix.LoginCsrf` with the same value, `MaxAge` default 600, `Path` = callback path, `SameSite=Lax`, `Domain` = callback hostname (or empty host-only).

On callback before exchanging the code:

1. Read cookie; require exact match with `state.Csrf`.
2. On mismatch or missing cookie → fail closed (no token exchange).
3. Clear the CSRF cookie after successful login callback (and on failed CSRF check).

Always on (not configurable off). Optional later: `LoginCsrfMaxAge` if needed; start with constant 600.

Double-redirect hop (`RedirectThenLogin`) does not set CSRF yet; CSRF is set when `redirectToProvider` runs the real IdP redirect (same as PKCE).

That hop runs whenever the callback origin differs from the request origin, including when PKCE is off. Otherwise the host-only cookie is stored on the app host and the callback never receives it.

## Consequences

- Parallel tabs: cookie name is `LoginCsrf.<csrf>` so each flow keeps its own cookie (avoids shared-cookie races).
- Logout state does not need CSRF cookie; skip for logout.
