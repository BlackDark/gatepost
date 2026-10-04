# Architecture Decision Records

This directory holds ADRs for this fork of [traefik-oidc-auth](https://github.com/sevensolutions/traefik-oidc-auth).

## Format

Each decision lives in `docs/adr/NNNN-short-title/` with:

| Path | Purpose |
|------|---------|
| `README.md` | The ADR (context, decision, consequences) |
| `plans/` | Optional supporting plans, reviews, spikes |

Number ADRs sequentially (`0001`, `0002`, …). Prefer short kebab-case titles.

### ADR template (Nygard-style)

```markdown
# NNNN. Title

**Status:** Proposed | Accepted | Deprecated | Superseded by ADR-NNNN
**Date:** YYYY-MM-DD
**Issue:** #N (if any)

## Context
What forces the decision.

## Decision
What we chose.

## Consequences
Good, bad, and follow-ups.
```

## Index

| ADR | Title | Status |
|-----|-------|--------|
| [0001](0001-pkce-verifier-in-oidc-state/) | PKCE code_verifier in OIDC state | Accepted |
| [0002](0002-sealed-oidc-state/) | Seal entire OIDC state | Accepted |
| [0003](0003-login-csrf-binding/) | Login CSRF cookie binding | Accepted |
| [0004](0004-oidc-nonce/) | OIDC nonce for ID tokens | Accepted |
| [0005](0005-standalone-ext-authz-service/) | Standalone ext_authz service (`cmd/gatepost-extauthz`) | Accepted |
