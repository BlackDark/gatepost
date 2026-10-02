# Code Review: `BlackDark/test-oidc-traefik-plugin`
**Version 1.0.0** · Multi-lane review (security, adversarial auth, Go quality, testing/CI, product, upstream/PR) · 2026-10-01

---

## AI READING INSTRUCTION

Read `[SPEC]` and `[BUG]` blocks for authoritative facts.
Read `[NOTE]` only for rationale and history.
`[?]` blocks are unverified — treat with lower confidence.

**Method caveat:** no Go toolchain in the review sandbox, so no `go test` / `go vet` / `-race` was executed. Every finding is verified by reading the cited lines, not by a reproducing test.

---

## 1. Verdict

**[SPEC]**

The cryptographic hardening is genuinely good and correctly implemented — sealed state, PKCE-verifier-in-state, login-CSRF binding, nonce, constant-time compares, `html/template` everywhere (no XSS), no alg-confusion, strict redirect-URI matching with an opt-in wildcard gate, 32-byte secret enforcement with `${file:}` support. Independently attacked and not broken: `alg:none`/HMAC confusion, CSRF-cookie tossing, callback-URL confusion, wildcard-redirect bypass.

The problems are elsewhere, and the top one is strategic, not a bug:

| # | Headline | Severity |
|---|---|---|
| 1 | **The fork's differentiators have all landed upstream.** Upstream `main` is ~3 weeks ahead and already fixes 2 of the top code findings below. | **Strategic** |
| 2 | Unauthenticated `Set-Cookie` amplification via attacker-controlled chunk count | **Critical** |
| 3 | `utils.Decrypt` panics on short ciphertext (unauthenticated remote panic) | **High** |
| 4 | Introspection `active:false` discarded at login → session minted from a dead token | **High** |
| 5 | Front-channel logout trusts bare `iss` → one-click forced logout for any user | **High** |
| 6 | JWKS: exclusive write lock held across an untimed network call → one slow IdP wedges all auth | **High** |
| 7 | CI never runs the subpackage tests that contain this fork's own hardening suite | **High** |

**[NOTE]** Findings 2–7 are, with the exception of the front-channel logout issue, already fixed or partially fixed upstream. See §5.

---

## 2. Critical

### [BUG] Unauthenticated memory-exhaustion DoS via session-cookie chunk count

- **Severity:** Critical · **Verified** (`src/cookie.go:73-83`, `src/cookie.go:99-112`)
- **Symptom:** one request from an anonymous client can make Traefik emit billions of `Set-Cookie` headers.
- **Cause:** `getChunkedCookieCount` does `strconv.Atoi(chunksCookie.Value)` with **no upper bound**, then `clearChunkedCookie` loops `chunkCount` times emitting a header each pass — without ever checking whether the chunk cookies exist (`readChunkedCookie` does, which is why only the clear path is exploitable). Reached pre-auth at `src/main.go:199`, and again at `:481` / `:596`.
- **Trigger:**
  ```
  GET / HTTP/1.1
  Cookie: TraefikOidcAuth.Session.Chunks=2000000000
  ```
- **Fix:** clamp in `getChunkedCookieCount` (`if chunkCount < 0 || chunkCount > 16 { return 0, errors.New(...) }`). `setChunkedCookies` uses 3072-byte chunks, so ≤16 covers ~48 KB of session state. Existing test only covers `Chunks=2`.

---

## 3. High

### [BUG] Remote unauthenticated panic in `utils.Decrypt`

- **Severity:** High · **Verified** (`src/utils/utils.go:219`)
- **Symptom:** `Cookie: TraefikOidcAuth.Session=QQ==` (3 decoded bytes) panics on `ciphertext[:12]`.
- **Cause:** no length check between `base64.DecodeString` and the nonce slice. Input is fully attacker-controlled via the session cookie (`src/session/cookieSessionStorage.go:31`) and via `?state=` (`src/oidc/state.go:47`).
- **Impact:** under Yaegi an unrecovered panic in a Traefik plugin can take down the whole proxy (all routers), not one connection.
- **Fix:** `if len(cipherbytes) < nonceSize+1 { return "", errors.New("ciphertext too short") }`. Also drop the `string` round-trip (two needless copies).

### [BUG] Introspection `active` flag discarded → login on a revoked token

- **Severity:** High · **Verified** (`src/main.go:406`)
- **Symptom:** with `provider.verificationToken: Introspection`, a token the IdP reports `active:false` still yields an authorized session cookie.
- **Cause:** `_, claims, err = toa.introspectToken(usedToken)` throws away the `active` bool; only `err` is checked at `:410`. `introspectToken` returns `(false, claims, nil)` for an inactive token (`src/oidc.go:280`).
- **Note:** the request path is correct (`src/session.go:196` honors `active`) — only the callback, where `IsAuthorized` is computed and the cookie minted, is wrong.
- **Fix:** capture and enforce `active`; add a mock-IdP test asserting no cookie is set on `{"active": false}`.

### [BUG] Front-channel logout accepts `iss` alone → forced-logout CSRF

- **Severity:** High · **Verified** (`src/main.go:558-591`)
- **Symptom:** `GET https://app/frontchannel-logout?iss=<idp-issuer>` wipes any logged-in victim's session.
- **Cause:** the `sid` check at `:579` is *conditional on `sid` being present*. `iss` is public and identical for every user, so it is not a per-session secret.
- **Fix:** require `sid` (or `id_token_hint`); compare with the existing constant-time helper. This is exactly what OIDC Front-Channel Logout 1.0 §2 mandates.

### [BUG] JWKS reload holds an exclusive lock across an untimed HTTP call

- **Severity:** High · **Verified** (`src/oidc/jwks.go:56-58`, `:91`; `src/config.go:283-286`)
- **Symptom:** one unresponsive IdP stalls authentication for **all** routers, permanently.
- **Cause:** `h.Lock.Lock()` is taken before a reload decision and held across `httpClient.Do` using `context.Background()`; the client has **no `Timeout`**, and `MaxIdleConns`/`IdleConnTimeout` are commented out. A reload failure also discards the cached keys instead of falling back.
- **Fix:** `http.Client{Timeout: 10s}`; `RLock` on the read path and lock only the reload; serve cached keys on reload failure; check `resp.StatusCode` in `loadKeys` (never checked today).

### [BUG] Data races on the token-validation path, and no `-race` in CI

- **Severity:** High · **Verified** (`src/oidc/jwks.go:104-181`; `src/main.go:48`, `:70-71`)
- **Symptom:** a key rotation during in-flight validation can return a torn key slice or panic.
- **Cause:** `RsaKeys`/`EcdsaKeys`/`CacheDate` are written under lock but read lock-free by `findRsaKey`/`findEcdsaKey`. Separately, `DiscoveryDocument` is read without a lock at `main.go:48` and published *before* `Jwks.Url` at `:70-71`, so a reader can see a non-nil doc with an empty JWKS URL. `ValidIssuer`/`ValidAudience` are likewise written at first request and read lock-free.
- **Fix:** snapshot key slices under `RLock` in `Keyfunc`; `sync.Once` for discovery; set `Jwks.Url` before publishing; resolve `ValidIssuer/ValidAudience` once in `New()`; add `go test -race ./...` (see §6).

---

## 4. Medium

**[SPEC]** Ordered by risk × likelihood.

| # | Issue | Evidence |
|---|---|---|
| M1 | Nil-deref + missing `return` in the `TokenValidation` `default:` branch — a config typo (`idToken`) panics **every** callback | `main.go:393-396`; not validated in `New()` |
| M2 | `err.Error()` on a legitimately-nil error at `session.go:36,57` and `main.go:196` — live with Introspection + `authorizationHeader` | `session.go:36` |
| M3 | No HTTP timeouts anywhere; `req.Context()` never propagated (discovery, token exchange, introspection, refresh, userinfo, JWKS all use `context.Background()`) | `config.go:283`, `oidc.go:47,118,225,301,368` |
| M4 | Client-supplied identity headers (`X-Auth-Request-User`, `X-Forwarded-User`, `Remote-User`) pass through untouched on bypass/forward paths — `sanitizeForUpstream` strips cookies only | `main.go:204-219`, `:184` |
| M5 | `X-Forwarded-Proto`/`Host` trusted unconditionally in the Traefik path → open redirect + attacker-controlled `redirect_uri`. `extauth-server` *does* gate this on `TRUSTED_PROXIES`; the plugin path does not | `utils.go:97-133` vs `extauth-server/main.go:127` |
| M6 | Sealed state and session blobs carry **no expiry** and **no purpose binding** (GCM AAD is `nil`) → indefinite replay; a session blob submitted as `?state=` decrypts into a zero struct | `oidc/state.go:9-22`, `utils.go:167` |
| M7 | No server-side session lifetime and no revocation: logout only clears the browser cookie, so a stolen cookie is unrecoverable. Not documented in `SECURITY.md` | `session/sessionStorage.go:15-27`, `main.go:481` |
| M8 | `verification_token: Introspection` never POSTs to `RevocationEndpoint`; `BackchannelLogoutSupported` is parsed and unused | `oidc/types.go:67,28` |
| M9 | Route dispatch uses unanchored `strings.HasPrefix` on raw `RequestURI` → `/logout-history` logs you out, `/logins` logs you in | `main.go:135,144,148,190` |
| M10 | Step-up (`unauthorizedBehavior: Challenge`) sends no `max_age` and never checks `auth_time` — docs promise a freshness guarantee the code doesn't deliver | `main.go:664` |
| M11 | `IsAuthorized` frozen in the cookie; `checkOnEveryRequest` defaults `false` → offboarding latency = token lifetime, unbounded | `main.go:443`, `config.go:63` |
| M12 | Query params override operator `authorizationParams` for every non-reserved key — `?acr_values=loa1&prompt=none` downgrades a configured AAL2/prompt policy | `main.go:810-824`, `:755` |
| M13 | Default `CookieNamePrefix` is identical for every instance → multi-tenant cookie collision and, with a shared `secret`, cross-tenant session acceptance | `config.go:56`, `cookie.go:133` |
| M14 | `getEllipticCurve` returns `nil` and `extractEcdsaKey` accepts it → nil-curve panic during ES* verification against a hostile/odd IdP JWKS | `oidc/jwks.go:246-280` |
| M15 | gRPC + HTTP ext_authz listeners have no TLS and no peer auth; any network-reachable caller can read `Set-Cookie` / `X-Auth-*` for forged requests. Documented as a known gap, still real | `extauth-server/grpc.go:137`, `main.go:83` |
| M16 | Token prefixes and **full** provider error bodies logged at INFO; `logAvailableClaims` dumps all claims incl. email/groups at DEBUG | `main.go:435`, `oidc.go:135,315,371` |
| M17 | OIDC discovery forced before the `bypassAuthenticationRule` check → an IdP outage 500s your explicitly-public `/health` | `main.go:112-131` |
| M18 | Header-template cache is dead: `HeaderConfig` is a value type, so `header.Template = tpl` writes to a copy and every request re-parses templates by reflection | `main.go:274-283` |
| M19 | `session_storage_type` is decoded and silently ignored — an operator can set `Redis` and get cookie storage with no warning | `config/config.go:41`, `config.go:298` |
| M20 | Numerous `http.Error(rw, err.Error(), …)` leak internal/provider error text to unauthenticated callers | `main.go:126,170,500,533,780+` |

**[?]** M14's panic is inferred from `crypto/ecdsa`'s handling of a nil `Curve`; the nil-curve-accepted path is directly visible, the crash was not reproduced.

**[?]** M5 and M9 require a proxy misconfiguration (`forwardedHeaders.insecure`) or an unusual app route name; both are config-dependent.

---

## 5. Upstream & PR status — the strategic headline

**[SPEC]**

| Item | State |
|---|---|
| Fork base | `sevensolutions/traefik-oidc-auth`, last merged upstream `2026-08-01` (`af618190`) |
| Upstream `main` HEAD | `2026-08-24` — **~3 weeks and 7 commits ahead** |
| Fork tags | `v0.22.0` (current), `v0.21.1`, `v0.21.0`, `v0.20.0`, `v0.19.0-hardening.1` |
| Upstream releases | latest `v0.21.0` (2026-07-26) |
| Open PRs | **1** — #6 `feat(extauth)!: Host-keyed multi-client YAML config` (+1265/−185, 23 files, breaking) |
| Closed PRs | #1–#5, all merged |
| Known CVEs found | none for `traefik-oidc-auth` |

**[BUG] Every headline feature of this fork now exists upstream**

- `04b5172c` feat: encrypt the callback state (#284)
- `2f6e3fd4` fix(pkce): store PKCE verifier in OIDC state (#283)
- `188a4be6` feat: improve redirect uri wildcard support (#286)
- `aa30f627` feat: split UnauthorizedBehavior into Unauthenticated/Unauthorized (#282)
- `dca8bc31` feat: AuthorizationParams (#279) · `32d4b6cd` feat: `${file:/path}` secrets (#280)

**[BUG] Upstream has already fixed two findings in this review**

| Upstream commit | Fixes |
|---|---|
| `0d3d5a81` — *bound the session cookie chunk count on read, write and clear* (#291) | §2 Critical, exactly |
| `73c01f8c` — *validate TokenValidation and header templates at config load* (#295) | M1 |
| `2452ab12` — *report a request without a session at debug level* (#296) | M20 (logging half) |
| `5d0b921c` — *handle missing/invalid JWT `kid` without panic* (#272) | M14 (family) |
| `fce7fed0` — *fix possible nil reference when refreshing the token* (#234) | M2 (family) |
| `823e99d1` — *avoid forced JWKS reload on token expiration* (#261) | §3 JWKS (family) |
| `bf0d45c9` — *add SBOM generation to release pipeline* (#299) | §6 supply-chain gap |

**[NOTE]** Consequence: the fork's stated value proposition (`README.md:14`, `.traefik.yml:9` "Hardened fork … sealed OIDC state, PKCE-in-state, login CSRF, nonce") is no longer differentiating against upstream. Continuing to rebase costs conflict surface in exactly the files the fork edits most (`src/main.go`, `src/oidc.go`, `src/utils/utils.go`, plus vendored Traefik predicate/rules code), while **not** rebasing means shipping a tree that is behind on real fixes. Pick a position deliberately:

- **(a) Rebase and reposition** as *security-first distribution + the ext_authz service* (upstream has no `cmd/extauth-server`; that is genuinely unique), or
- **(b) Go standalone** and drop the "hardened fork" framing entirely.

**[?]** `.backportrc.json` still targets `sevensolutions/traefik-oidc-auth@production`. Whether that branch still exists and is maintained was not verifiable; a stale target silently yields zero patches.

### Process hygiene (verified, cheap)

**[SPEC]**

- `SECURITY.md:5-10` routes vulnerability reports to two **upstream maintainers' personal emails**. A reporter of a fork-specific bug has no correct channel and may disclose into upstream's inbox. Add a `contacts.security` entry for this repo.
- `README.md:3,4,7,14` still renders upstream's CI badge, LICENSE link and repo link — badge rot points users at upstream releases as if they were this fork's.
- No `CHANGELOG.md`, no `VERSION` file; `v0.20.0` shipped a **breaking** config split documented only inside `website/`. No workflow builds or deploys `website/`.
- `.traefik.yml:5` / `go.mod:1`: `github.com/BlackDark/test-oidc-traefik-plugin` — a scratch name that will never appear in the Traefik catalog. One-hour mechanical change that gates every catalog effort.

### PR #6 — open, breaking, unreviewed

**[SPEC]** Host-keyed multi-client YAML for `extauth-server`; removes single-client JSON `CONFIG_FILE`; per-client `secret` + `cookieNamePrefix`; hot reload via file watch and `SIGHUP`; unknown Host → 403.

**[NOTE]** Sound direction, and it directly attacks the multi-tenant cookie-collision problem (M13) at the right layer. Blockers before merge:

1. **Every box in its own test plan is unticked.** `go test`, multi-file boot, unknown-Host 403, per-client isolation, and bad-YAML-keeps-old-config are all unverified in the PR description.
2. **`SECRET_WATCH_DIRS`** widens secret-file watching to a directory — needs an explicit threat note (symlink following, TOCTOU, world-readable mounts).
3. **Bad-reload-keeps-previous-map** is correct, but needs a test proving a partially-valid file (one bad client among N) does not silently drop clients or half-apply secrets.
4. **Host-keyed routing is a tenant-isolation boundary.** It needs the same `TRUSTED_PROXIES` posture as M5, otherwise `Host` is attacker-controlled — the PR description itself flags this as unconfirmed.
5. It is `!`-breaking on a component the README calls experimental; the breaking-change note belongs in a `CHANGELOG.md` entry, which does not exist.

---

## 6. Testing & CI gaps

**[SPEC]**

| # | Gap | Evidence |
|---|---|---|
| T1 | **CI never runs the subpackage tests** — `go test` with no `./...` in `./src`, so `oidc/state_test.go` (the entire tamper-rejection suite), `utils/utils_test.go` (wildcard redirect hardening, 322 lines), `oidc/jwks_test.go`, `rules/` **never execute**. A regression that unseals attacker-forged state lands green. | `.github/workflows/testing.yaml:42-44`; same bug in `taskfile.yml:56-58` |
| T2 | No `-race` anywhere — the §3 races are exactly what it catches | grep across workflows + taskfile: zero hits |
| T3 | The `keycloak` e2e project (the only `cABundle`/custom-CA tests) never runs in CI; only `--project=mock-oidc` | `e2e-tests.yml:53` vs `playwright.config.ts:22-26` |
| T4 | `Dockerfile` hand-rolled cross-compile (arm64 path, `TARGETARCH` mapping) is **never built or smoke-tested** anywhere — only inside the release job, after publish | `extauth-server/Dockerfile:8-13` |
| T5 | Release publishes `:latest` from **any** `v*` tag and from arbitrary `workflow_dispatch` refs (`tag: main` → `:latest`), with no semver validation and no prerelease guard | `release-extauth-server.yml:6,35,73,84-86` |
| T6 | `org.opencontainers.image.revision` uses `github.sha` while the build checks out a different ref → false provenance for an auth component | `release-extauth-server.yml:55,89` |
| T7 | Dependabot covers neither the `cmd/extauth-server` **module** nor `e2e/` (bun) — a grpc / `x/net` CVE has no automated update path | `.github/dependabot.yml` (2 entries) |
| T8 | `govulncheck@latest`, `bun-version: latest`, `golang:1.26-alpine`, `distroless/…:nonroot` — all floating, in the same series that SHA-pinned the actions | `lint.yml:65,86,105,130`; `Dockerfile:1,11` |
| T9 | `testing.yaml:34-36` runs `go get .` against a repo with a committed `vendor/` and `modules-download-mode: readonly` — CI may test a *different* dependency set than ships | `.golangci.yml:3` |
| T10 | 572-line hand-rolled AST expression evaluator (`src/predicate/`) and `validateTokenLocally` have **zero** tests; `handleCallback` is ~150 lines of security-critical branching with no complexity lint | `src/predicate/*`, `src/oidc.go:149` |
| T11 | `NODE_TLS_REJECT_UNAUTHORIZED=0` set in `beforeAll` and never restored, on top of `ignoreHTTPSErrors: true` — a broken or MITM'd cert **cannot fail** the suite | `mock-oidc/tests.spec.ts:53`, `keycloak/tls.spec.ts:13` |
| T12 | `.dockerignore` excludes only `.git` + two `node_modules`, while `Dockerfile` does `COPY . .` and `taskfile.yml` documents a `.env` in `workspaces/` — local builds can bake real IdP secrets into a build layer | `.dockerignore`, `Dockerfile:3` |

**[NOTE]** What *is* solid and should be preserved: `.golangci.yml` is well tuned with per-line justifications on every `gosec` exclusion; the zizmor job is correctly configured (SHA-pinned action, `persona: pedantic`, `permissions: {}` at top with per-job grants); the Go tests that *do* run are real tests, not smoke tests; Playwright uses `workers: 1` + `forbidOnly` in CI, which is right for a shared docker-compose stack. The problem is not test quality — it is that a third of the suite is never invoked.

---

## 7. Feature gaps, ranked

**[SPEC]** Value × effort, for an auth gateway.

| # | Gap | Value | Effort |
|---|---|---|---|
| F1 | Bounded session lifetime (`MaxSessionLifetime` + idle timeout) — prerequisite for making *any* honest claim about offboarding and revocation latency | High | **S** (1 field + 1 check) |
| F2 | Reject or delete `session_storage_type` — silent no-op config is worse than absent config | High | **XS** |
| F3 | `/healthz` + `/readyz`, graceful shutdown, auth-decision logs at INFO, Prometheus counters — the component that gates everything is the one whose failures are invisible | High | S–M |
| F4 | Logout revokes the token (`RevocationEndpoint`) + signed back-channel logout receiver | High | M |
| F5 | Real repo identity + `CHANGELOG.md` + docs deploy — gates every catalog/adoption conversation | High | **XS** |
| F6 | Step-up that actually enforces freshness (`max_age` + `auth_time`) — currently advertised but not implemented (M10) | Medium | S |
| F7 | Nightly `keycloak` e2e project (T3) | Medium | XS |
| F8 | Claim-based access rules / per-route audience | — | **already solvable**: Traefik instantiates plugins per middleware, so a second middleware *is* per-route audience. Docs example only. |

**[NOTE]** Explicitly **not** worth building: multi-IdP failover / multi-provider (operationally solved by chaining two middlewares; the state-machine cost is enormous for a narrow HA case), PAR / DPoP / JAR (already skipped in `docs/tasks.md:77`). Recording the first as an explicit non-goal next to the others is worth more than building it.

---

## 8. Code-quality notes (non-security)

**[SPEC]**

- **Dead code:** `SessionStorageType`/`SessionStorageTypeCookie` (M19); `oidc.OidcIntrospectionResponse`; `sessionId string` param ignored by `CookieSessionStorage.StoreSession`; a `// TODO: Remove` block at `oidc.go:270`.
- **Duplication:** `exchangeAuthCode` and `renewToken` are ~90% identical form-POST blocks; the "parse → force-reload JWKS → re-parse" block is duplicated verbatim at `oidc.go:170-190` and `:378-397`. Any fix (size limits, `Content-Type`, context) must be applied in 4 places.
- **Premature abstraction:** `session.SessionStorage` has exactly one implementation and exists only to be exported to a separate Go module that needs three symbols (`CreateConfig`, `New`, `ServeHTTP`) but gets nine, including mutable internals (`DiscoveryDocument`, `Jwks`, `Lock`, `Config`). Deleting `cmd/extauth-server/go.mod` would remove that API pressure outright.
- **Dead cache** (M18) — per-request template re-parse under load.
- **Config validation gaps:** `New()` validates secret, `tokenRenewalThreshold`, CA bundle and header values, but **not** `tokenValidation` (M1), `sameSite`, `includeWhen`, `authorizationParams` reserved keys, or the presence of required discovery endpoints — an IdP without `introspection_endpoint` passes startup and fails per-request.
- **Fork divergence:** fork-local changes are interleaved in upstream's hottest files with no marker block at the top. Add a "fork-local changes" header comment per file so rebase conflicts are attributable.

**[NOTE]** Naming is otherwise clean and the package split (`oidc`, `session`, `rules`, `predicate`, `utils`, `logging`, `errorPages`) is reasonable. One idiom to drop: `err.Error()` used in format strings where `%v`/`%w` on the error value is correct and panic-free (M2).

---

## 9. Suggested sequencing

**[SPEC]**

1. **Today (XS/S, no design needed):** §2 chunk-count clamp · §3 `Decrypt` length guard · M1 `return` + nil-safe error · M2 `%v` instead of `err.Error()` · F2 reject `session_storage_type` · F5 rename + `CHANGELOG.md` · `SECURITY.md` contact.
2. **This week:** T1 `./...` and T2 `-race` (these gate confidence in everything else) · M3 HTTP timeouts + context propagation · M5/M9 proxy-trust and route matching · M20 generic client-facing errors.
3. **Decide (blocking the rest):** §5 (a) rebase-and-reposition vs (b) go standalone. Then T8 pin the floating toolchain/base images, T5/T6 release guards, T4 build-and-smoke-test the image, T7 extend Dependabot.
4. **Then the capability work:** F1 bounded session lifetime → F4 revocation + back-channel logout → F3 observability → F6 step-up freshness. F1 first because it is the prerequisite that makes F4, F6 and the offboarding-latency claim (M11) coherent.
5. **Ongoing:** T3/T10 real-IdP and `predicate`/`validateTokenLocally` coverage.

---

## 10. What is already right — do not regress

**[SPEC]**

- Sealed state: AES-GCM, fresh random nonce per seal, PKCE verifier inside the sealed JSON, `S256` only, 32-byte verifier.
- `reservedAuthorizationParams` correctly blocks client override of `code_challenge`, `nonce`, `state`, `redirect_uri`, `response_type`, `client_id`, `scope`, `resource` (note: the *unreserved* half is M12 — that is the gap, not the mechanism).
- Login-CSRF cookie is host-only, `HttpOnly`, cleared on success **and** failure, with the token embedded in the cookie *name* so a domain-wide attacker cookie cannot shadow-and-substitute it.
- `Keyfunc` rejects `none`/HMAC and requires `kid`; cross-family confusion is blocked by library type assertions. **No alg-confusion.**
- Redirect-URI matching: exact by default; wildcards behind a process-wide `TOA_ENABLE_REDIRECT_URI_WILDCARDS` opt-in; `unsafeWildcardRedirect` blocks `//`, userinfo `@`, and iterative percent-decoded `..` traversal; the authority template compiles a quoted regex (no ReDoS).
- Error pages use `html/template` throughout — **no XSS found**, including operator-supplied templates.
- `sanitizeForUpstream` strips all internal cookies before proxying; header templates use `text/template` with `JSEscape`.
- `extauth-server` gates `X-Forwarded-*` on `TRUSTED_PROXIES` with an empty-by-default fail-closed posture, bounds-checks status codes, and has a panic recovery interceptor.
- 32-byte secret enforcement, default-secret refusal, `${file:/path}` support.
- New session ID (UUIDv4) per login — **no session fixation**.

---

## Changelog

- **1.0.0** (2026-10-01) — Initial review. 6 lanes (security, adversarial auth, Go quality, testing/CI, product, upstream/PR). 1 critical, 5 high, 20 medium, 12 CI/test, 8 feature. Upstream/PR research performed directly after the delegated lane failed (no web tools in that agent).
