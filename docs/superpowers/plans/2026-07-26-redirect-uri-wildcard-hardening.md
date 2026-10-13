# Redirect URI Wildcard Hardening Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make redirect URI wildcards secure and explicitly opt-in while preserving exact-match behavior by default.

**Architecture:** Extend redirect validation with an instance-wide wildcard flag loaded from `TOA_ENABLE_REDIRECT_URI_WILDCARDS`. Exact entries always match; enabled wildcard templates receive strict host/path matching plus spoofing and traversal guards. Existing callback re-validation uses the same matcher.

**Tech Stack:** Go 1.26, Traefik Yaegi plugin, standard library tests, Docusaurus Markdown.

## Global Constraints

- Exact URI matching remains enabled without configuration.
- Wildcards require `TOA_ENABLE_REDIRECT_URI_WILDCARDS=true` or `1`.
- Bare `*` is literal unless wildcard mode is enabled.
- Reject protocol-relative, user-info spoofing, and path traversal in wildcard mode.
- Keep fork camelCase documentation conventions.
- Do not import upstream version bumps or AI policy.

---

### Task 1: Redirect matcher tests

**Files:**
- Modify: `src/utils/utils_test.go`

**Interfaces:**
- Consumes: existing `ValidateRedirectUri`
- Produces: expected signature `ValidateRedirectUri(string, []string, bool)`

- [ ] Add exact-match and opt-in tests.
- [ ] Add host-label, multi-segment path, query/fragment, spoofing, and traversal cases.
- [ ] Run focused test and confirm compile failure before implementation.

### Task 2: Harden redirect matching and integrate configuration

**Files:**
- Modify: `src/utils/utils.go`
- Modify: `src/config.go`
- Modify: `src/main.go`

**Interfaces:**
- Produces: `ValidateRedirectUri(redirectURI string, validURIs []string, wildcardsEnabled bool)`
- Produces: `TraefikOidcAuth.RedirectURIWildcardsEnabled bool`

- [ ] Implement exact-match-first validation.
- [ ] Implement constrained host/path wildcard matching.
- [ ] Load and validate `TOA_ENABLE_REDIRECT_URI_WILDCARDS`.
- [ ] Warn when wildcard-looking entries are configured while disabled.
- [ ] Pass flag through login, callback, and logout validation.
- [ ] Run focused and full Go tests.

### Task 3: Documentation cleanup

**Files:**
- Modify: `docs/guide/getting-started/middleware-configuration.md`
- Modify: `README.md`

- [ ] Document exact-match default and wildcard opt-in using camelCase keys.
- [ ] Document host/path semantics and rejected unsafe values.
- [ ] Remove expired hosting-provider promotion.
- [ ] Run Markdown/Biome checks.

### Task 4: Verification and review

**Files:**
- Review all branch changes.

- [ ] Run Go tests.
- [ ] Run golangci-lint/gosec and govulncheck.
- [ ] Run website/e2e lint.
- [ ] Run mock OIDC E2E suite.
- [ ] Request critical subagent review.
- [ ] Fix all Critical/Important findings and re-review.
- [ ] Commit coherent parts and push branch.
