# E2E Design: fast custom-CA (TLS) coverage without Keycloak

**Status:** implemented (Phases 1 and 3 landed; Phase 2 pending) · **Author:** multi-lane review + research · **Date:** 2026-10-03

---

## AI READING INSTRUCTION

Read `[SPEC]` and `[BUG]` for authoritative facts.
Read `[NOTE]` for rationale, evidence and open questions.
`[?]` blocks are unverified — treat with lower confidence.

---

## 1. Decision

**[SPEC]** Add a third Playwright project, `mock-oidc-tls`, that runs the **existing**
`ghcr.io/navikt/mock-oauth2-server:5.0.2` image **over HTTPS with a self-supplied
PKCS#12 keystore**, so `provider.cABundle` / `provider.cABundleFile` are exercised on
**every pull request** instead of only on `main`. Keycloak was removed in the same change;
see Phase 3 for the decision and the residual gaps it accepts.

| | |
|---|---|
| New containers | **0** — same image, one extra config block |
| Databases | none |
| IdP boot | ~3 s (same as today's `mock-oidc` suite, which is green) |
| Certificate generation | < 1 s |
| PR gating | yes |
| Replaces | the only two assertions `keycloak` uniquely provides |

**[NOTE]** This is deliberately *not* a rewrite. The repo already depends on this exact
image and config format; the change is "turn on TLS, bring our own certificate".

### The one thing that makes it work

**[BUG] `"ssl": {}` cannot be used — it mints a random self-signed certificate at every boot**

Verified in `Ssl.kt` (`src/main/kotlin/no/nav/security/mock/oauth2/http/Ssl.kt`):

```kotlin
class SslKeystore @JvmOverloads constructor(
    val keyPassword: String = "",
    val keyStore: KeyStore = generate("localhost", keyPassword),   // <-- random per boot
)
```

`"ssl": {}` selects the default `SslKeystore`, whose default `keyStore` is
`generate("localhost", …)` — a freshly generated self-signed certificate. Its CA is
therefore different on every run, and could never be handed to `cABundle`. The config
must use the *bring your own* constructor, which takes a keystore file.

**[SPEC]** `httpServer` must be `NettyWrapper` (the other wrapper does not serve TLS),
and `keystoreType` is `PKCS12` or `JKS`.

Sources:
- README §HTTPS — <https://github.com/navikt/mock-oauth2-server/blob/5.0.2/README.md#https>
- `Ssl.kt` — <https://github.com/navikt/mock-oauth2-server/blob/5.0.2/src/main/kotlin/no/nav/security/mock/oauth2/http/Ssl.kt>
- upstream's own reference stack — <https://github.com/navikt/mock-oauth2-server/blob/5.0.2/docker-compose-ssl.yaml>

### The negative case is the whole point

**[SPEC]** The existing `tls.spec.ts` has only two **positive** assertions
(`cABundleFile` works, inline `cABundle` works). Both can pass for the wrong reason —
if the bundle were silently ignored and the IdP were somehow still reachable, both stay
green. A test with no negative case does not prove the bundle is honoured; it only
proves the IdP was reachable.

---

## 2. Why not the alternatives

| Option | Why not |
|---|---|
| Keep Keycloak | ~3 min boot, postgres, realm import, 4096-bit CA chain; was red on `main` and had to be gated to non-PR refs. It is the *only* slow thing in the suite, and it is slow for reasons our code does not care about. |
| In-process bun/node HTTPS IdP | Measured: an in-process HTTPS server listens in **8 ms**, so it is genuinely faster than the 3 s container. But it does **not** remove Docker — Traefik and `whoami` still need containers — so it trades a 3 s container for container→host networking plus a second cert-management path. Only worth it if we also drop Docker for Traefik, which is unproven. |
| nginx/caddy TLS terminator in front of the mock | Workable fallback if native TLS fails. Costs one more container, one more config file, and one more thing that can be the slow one. |
| Zitadel / Dex / Hydra / Logto / Pocket ID | All heavier (database or a larger image) for strictly less coverage than a mock we already control. |

**[NOTE]** A measurement worth recording because it contradicts the obvious assumption:
certificate generation is **not** the bottleneck. The existing `gencerts.sh` (two
4096-bit RSA keys + a two-level chain) takes **0.366 s**; a single ECDSA P-256 leaf takes
**0.006 s**. Against a Keycloak boot measured in minutes, optimising the cert pipeline
buys nothing. Use 2048-bit RSA or ECDSA P-256 anyway — it is free — but do not justify the
design by it.

---

## 3. What the suite must assert

**[SPEC]** One stack, one Traefik, config rewritten per case via `configureTraefik`.
Status codes alone are not sufficient; each case also asserts a plugin log marker.

| # | Case | Expect | Distinguishing signal |
|---|---|---|---|
| T1 | `cABundleFile` = correct bundle | login succeeds | `Loaded CA bundle from` (DEBUG) |
| T2 | inline `base64:` of the same file | **identical observable to T1** | `Loaded CA bundle provided inline` |
| T3 | **no bundle at all** | **fails** | `x509: certificate signed by unknown authority` |
| T4 | bundle for a **different** CA | **fails** | `Loaded CA bundle from` **present** + `x509:` **present** |
| T5 | `cABundleFile: ""` | same as T3 | empty ≡ unset |
| T6 | bundle file contains garbage | fails | WARN `Failed to append CA bundle` — the only thing separating this from T3 |
| T7 | `cABundle: "base64:!!not base64!!"` | rejected at load | plugin logs `Failed to base64-decode the inline CA bundle`, then `New()` returns an error |
| T8 | `cABundleFile: /nonexistent` | rejected at load | plugin logs `Failed to load CA bundle from …`, then `New()` returns an error |
| T9 | both options set | rejected at load | plugin logs `You can only use an inline CABundle OR CABundleFile, not both.`, then `New()` returns an error |

**[SPEC]** Two orthogonal channels make each case unambiguous:

1. **Plugin log prefix.** Every plugin line is `[traefik-oidc-auth]`. *Present* ⇒ the
   middleware was constructed and reached a decision. *Absent* ⇒ `New()` rejected the
   config — a completely different bug (T7–T9).
2. **Log content.** `Loaded CA bundle …` proves the option was *parsed*;
   `Failed to append CA bundle` proves it was *malformed*; `x509: …` proves TLS was
   *rejected*. Without the middle one, T6 is indistinguishable from T3.

**[SPEC]** T2 must assert **equivalence with T1** (same redirect target, same final
status), not merely "it worked". Two independent "it worked" tests prove nothing about
the two options being equivalent.

**[NOTE] "plugin never logs" was wrong in the table above, and T7–T9 assert on a log
line instead of on a status code.** `New()` returns an error, but it does so *after* it
has already logged the specific reason (`src/config.go`, the base64 decode and
`os.ReadFile` branches). Those lines are the deterministic signal; the HTTP status Traefik
then returns is an internal detail (404 or 500 depending on Traefik's internals) that this
change deliberately does not pin. See "Load-time rejections" below.

**[NOTE]** A dead IdP must not be able to masquerade as a TLS rejection. Every negative
case needs an in-test liveness check against the mock (`/isalive`) so that "IdP is down"
and "IdP's certificate was rejected" cannot produce the same green result.

---

## 4. Mechanics

**[SPEC]**

| File | Change |
|---|---|
| `e2e/tests/mock-oidc-tls/gencerts.sh` | new — leaf cert (2048-bit RSA or ECDSA P-256), self-signed CA, `openssl pkcs12 -export`, **plus a second unrelated `other_ca.pem`** for T4 |
| `e2e/tests/mock-oidc-tls/config.json` | new — today's `mock-oidc/config.json` verbatim, plus the TLS block |
| `e2e/tests/mock-oidc-tls/docker-compose.yml` | new — mock on `8443`, its own Traefik on `9180/9543/8180`, `extra_hosts: localhost:172.17.0.1` so the container can reach the host-published mock, `./certificates` mounted into **both** mock and Traefik |
| `e2e/tests/mock-oidc-tls/tls.spec.ts` | new — T1–T9 |
| `e2e/playwright.config.ts` | add project `mock-oidc-tls` |
| `e2e/utils.ts` | `configureTraefik(yaml, { file, wait })` |
| `.github/workflows/e2e-tests.yml` | new job `test-tls`, a **sibling of `test`**, so it inherits no `if:` gate and runs on PRs |
| `.dockerignore` | add `e2e/tests/mock-oidc-tls/certificates/` |

**[BUG] `e2e/utils.ts` writes one fixed `e2e/.http.yml` shared by every project**

Two stacks in one `playwright test` run overwrite each other's Traefik config. The new
project needs its own filename (`.http-tls.yml`) or its own CI job, or both.

**[SPEC]** Negative cases must not use the waiting `configureTraefik`: when `New()`
returns an error the config is never live, so the helper would poll for the full timeout
and then fail with "config not ready" — which reads like a Traefik problem, not a
config problem. Add `{ wait: false }` and poll for the expected failure signature with a
short `expect.poll`.

**[NOTE]** The healthcheck needs adjusting: the mock's `/isalive` is now HTTPS, so it
requires `wget --no-check-certificate` (upstream's own compose uses plain `wget` because
its example is HTTP-only).

**[NOTE] Load-time rejections (T7–T9) are asserted on the plugin's log line, not on an
HTTP status.** A config whose middleware constructor returned an error never becomes a
router, so the status Traefik answers with depends on Traefik's internals. That was traced
by reading Traefik but deliberately **not pinned** in a test: asserting `404` would encode
an unverified implementation detail and break for the right behaviour whenever Traefik
changes it. The implemented tests assert the specific log line (deterministic, written
while Traefik parses the config) plus "the response is not 200". Note the plugin's error
lines are logged *before* `New()` returns, so they are present even though the router is
never registered — that is the whole reason the log is the right channel.

**[NOTE] Certificate generation is verified, not assumed.** `gencerts.sh` runs in 0.14 s
(measured, versus 0.366 s for the old 4096-bit two-level chain it replaces), and the
artefacts were checked before the tests were written:
`openssl verify -CAfile ca.pem website.pem` → `OK`;
`openssl pkcs12 -info -in mock_oidc.p12 -passin pass: -nokeys` → readable, and the store
contains both the leaf and the CA; `openssl verify -CAfile other_ca.pem website.pem` →
`error 20 … unable to get local issuer certificate`, which is the T4 precondition.

---

## 5. The larger gap: no new option is covered end-to-end

**[SPEC]** Verified by grep across `e2e/**`: **zero** coverage for
`maxSessionLifetimeSeconds`, `sessionIdleTimeoutSeconds`, `trustedProxies`,
`authorizationParamsOverridable`, `sessionStorageType`, `provider.revokeTokensOnLogout`,
`provider.maxAuthAgeSeconds`, `provider.oidcTimeoutSeconds`.

**[SPEC]** These need **no TLS and no new stack** — they belong against the existing fast
plain-HTTP `mock-oidc` project.

| Option | Cheap assertion |
|---|---|
| `authorizationParamsOverridable` | one 302 `Location`: configured `acr_values=aal2` is pinned unless the key is allowlisted; `?acr_values=loa1` downgrades only when allowlisted |
| `sessionStorageType` | `"Cookie"` → works; `"redis"` → rejected at startup with `invalid session_storage_type` |
| `provider.oidcTimeoutSeconds` | point the provider at a worker-local slow server; `1` → failure, `10` → works |
| `sessionIdleTimeoutSeconds` / `maxSessionLifetimeSeconds` | login → 200 → wait bound → 302 back to the IdP. Differential: set the *other* bound high so only the intended one can fire |
| `trustedProxies` | untrusted half: browser sends `X-Forwarded-Host: evil.example`, assert the `redirect_uri` ignores it. **Trusted half needs a raw HTTP client from a known source IP** — a browser cannot change its own `RemoteAddr`, so this needs a pinned-IP service in the compose file |
| `provider.maxAuthAgeSeconds` | `unauthorizedBehavior: Challenge` + an `auth_time` claim in the token callback → denied; `maxAuthAgeSeconds: 0` → allowed |
| `provider.revokeTokensOnLogout` | no clean browser-observable. **[NOTE]** The mock does implement a revocation endpoint, so it *is* assertable, but only via logs or a direct API call. A Go unit test already covers the behaviour properly — prefer that and say so in a comment rather than scraping logs. |

---

## 6. Phased plan

**[SPEC]**

**Phase 1 — custom-CA coverage on every PR.** New stack + T1–T9 + `test-tls` job.
~5 min added to a PR's wall clock as a parallel job. Low risk: if it is flaky it is a
separate job, not a new failure mode in the green suite.

**Phase 2 — the eight config options.** Against the existing fast stack, no TLS needed.
Ship the six cheap ones first; `revokeTokensOnLogout` and `maxAuthAgeSeconds` are the two
that need evidence about the mock's behaviour before they can be written.

**Phase 3 — Keycloak.** **TAKEN: Keycloak is REMOVED**, not moved to nightly.
**[SPEC]** This landed with Phase 1. Deleted in one change: `e2e/tests/keycloak/**`
(`docker-compose.yml`, `master-realm.json`, `gencerts.sh`, `data/`, `tls.spec.ts`), the
`keycloak` Playwright project, the `E2E tests (keycloak)` workflow job, the
`prepare:keycloak` / `test:keycloak` package scripts, and the Keycloak lines in
`.dockerignore`. `mock-oidc-tls` now carries the custom-CA coverage on every PR.

**[NOTE] Why deleting outright was acceptable, not merely tolerable.** The earlier
proposal in this section argued for a nightly with `continue-on-error: true` first. That
was the right call when the alternative was *no* coverage, and it is now superseded:
`mock-oidc-tls` exists, so there is no window in which the custom-CA path is unasserted.
Two further facts settled it:

1. **Keycloak's load-bearing coverage was two tests, and both were TLS-to-provider.** The
   entire `keycloak` suite was `tls.spec.ts` with exactly two cases —
   `cABundleFile` positive and inline `cABundle` positive. T1–T9 is a strict **superset**
   of what those two proved (same two, plus seven negatives), so nothing observable was
   lost and a lot was gained.
2. **The plugin-side behaviours Keycloak *appeared* to cover are already covered by unit
   tests.** Token introspection plumbing, refresh-token revocation, PKCE generation and
   claim authorization are all exercised in `src/**_test.go` against httptest fakes. The
   marginal value of a real IdP there was conformance of the *provider*, which is exactly
   the axis this document now records as an accepted gap (below) rather than one a
   75-minute flaky job was buying.

**[NOTE] What a nightly would have bought, stated honestly.** A nightly keeps a real IdP
running for exactly one thing: conformance. Nothing else. Given the residual gaps below
are real and permanent, the case for retaining a slow container purely to observe them was
weak, and the cost was a permanently-red or permanently-ignored job.

### Residual gaps — ACCEPTED LIMITATIONS, not passing guarantees

**[SPEC]** These follow from the replacement IdP's actual behaviour. They are accepted
deliberately. None of them is covered by anything else in `e2e/`, and no test in this repo
claims otherwise.

| Provider capability Keycloak exercised | mock-oauth2-server 5.0.2 | Consequence |
|---|---|---|
| Rejects a `redirect_uri` it was not registered with | does **not** validate `redirect_uri` | Nothing in e2e proves the plugin's `callbackUri` / `redirect_uri` is one a strict provider would accept. A provider that rejected it would surface as a 400 at the token endpoint; we would not see it here. |
| Rejects a bad `client_secret` | does **not** check `client_secret` | Nothing in e2e proves the plugin sends the configured secret correctly, or that a wrong secret fails. Only the *presence* of the field is exercised. |
| Requires a PKCE `code_verifier` | a **missing** verifier is silently accepted; a **wrong** one is rejected | See the PKCE note below. |
| Emits a `sid` claim | does **not** | Nothing in e2e exercises the front-channel logout path against a provider that actually keys logout on `sid`. |
| Discovery document with `*_supported` metadata arrays | omits every `*_supported` array | The plugin's metadata handling is not exercised against a document that advertises capabilities. |

**[SPEC]** None of these is a passing guarantee. Each is a place where a future real-provider
regression would be invisible to CI. They are recorded here so that anyone treating green
CI as "the plugin works against a standards-compliant IdP" knows it is not what was
measured.

**[NOTE] Compensating coverage added in the same change — and its exact limit.** The
`mock-oidc` project previously ran with `usePkce: false` everywhere, so PKCE had **zero**
end-to-end coverage anywhere in the repo once Keycloak went. A dedicated `usePkce: true`
middleware on `PathPrefix(/pkce)` (with its own `/oidc/callback` router, so the callback
returns through the same plugin instance that produced the challenge) was added, plus one
test that logs in through it.

What that test proves: the plugin's S256 round trip works against a real OIDC
implementation — it emits `code_challenge` + `code_challenge_method=S256`, retains the
verifier, and replays it on the token leg, and the exchange succeeds.

What it does **not** prove: that a provider would reject a PKCE **downgrade**. Because the
mock silently accepts a *missing* verifier, a plugin that dropped the verifier entirely
would still pass that test. Only a *wrong* verifier is rejected, so the test constrains
"not wrong", not "not absent". Writing a test that implied otherwise would be a false
guarantee rather than a test, so none was written.

Sources (mock-oauth2-server, tag `5.0.2`):
- Authorize/token handlers — <https://github.com/navikt/mock-oauth2-server/tree/5.0.2/src/main/kotlin/no/nav/security/mock/oauth2/server>
- Issuer/discovery document assembly — <https://github.com/navikt/mock-oauth2-server/tree/5.0.2/src/main/kotlin/no/nav/security/mock/oauth2/issuer>
- README (documented HTTPS/keystore shape, `/isalive`) — <https://github.com/navikt/mock-oauth2-server/blob/5.0.2/README.md>

**[NOTE]** Do not do Phase 3 without Phase 1. If the fast TLS suite does not exist, the
custom-CA path drops to **zero** assertions anywhere in the repo when Keycloak goes.

---

## 7. Acceptance checklist for any future e2e tool

**[SPEC]** Apply this to any candidate before adopting it:

1. **Deterministic readiness signal** on a documented endpoint, with a healthcheck that
   asserts *semantics*, not liveness. The Keycloak probe must check `200` **and**
   `status: UP`, because its management port opens before the realm import finishes —
   that is precisely the race that made the job red.
2. **No database.** A postgres sidecar disqualifies a candidate from PR gating.
3. **Pinned image**, tag *and* digest; certificates generated fresh per run, never committed.
4. **Cold boot under 30 s**, with `start_period + retries × interval` written into the compose file.
5. **No network egress** beyond the runner.
6. **Bounded cleanup**, plus a CI step that dumps `compose ps -a` and logs on failure —
   `afterEach` does not run when `beforeAll` fails, which is the likeliest failure mode.
7. **No test-order coupling:** every case rewrites the whole dynamic config and waits for
   its own observable; any single case must be runnable first with `-g`.
8. **Can produce the awkward inputs** — arbitrary claims, a revocable refresh token, a
   private-CA leaf — or those cases are explicitly out of scope.
9. **It can fail for the right reason**, and there is a test proving the positive case
   would fail if the mechanism broke.

---

## Changelog

- **1.1** (2026-10-03) — Phase 3 recorded as **TAKEN**: Keycloak removed rather than
  moved to nightly, with the accepted residual gaps stated. T7–T9 corrected to assert the
  plugin's own load-time error lines; the unverified 404-vs-500 question is closed by not
  asserting a status. Certificate-generation claims marked verified.
- **1.0** (2026-10-03) — initial proposal.