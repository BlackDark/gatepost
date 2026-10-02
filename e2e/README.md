# E2E Tests

End to end tests are executed by using [*Microsoft Playwright*](https://playwright.dev/).
The test infrastructure is set up by [*docker compose*](https://docs.docker.com/compose/).

Test files are located in the *./tests*-folder within subfolders for different configurations or IDPs.

We're using *bun* which can be installed by following the [official instructions](https://bun.com/docs/installation).

## First-time setup
```
bun install
bunx playwright install
```

## How to run the tests
```
bunx playwright test
```

You can also run the tests and watch the browser, or use the interactive UI mode:

```
bunx playwright test --headed
```
```
bunx playwright test --ui
```

## The two projects, and what each covers

There are two Playwright projects, both against `ghcr.io/navikt/mock-oauth2-server:5.0.2`.
They publish different host ports (9080/9443/8080 vs 9180/9543/8180) and write to
different Traefik config files (`.http.yml` vs `.http-tls.yml`), so both stacks can be up
at the same time and neither can overwrite the other's config mid-run.

```
bun run prepare          # pulls images for the mock-oidc project
bunx playwright test --project=mock-oidc
```

```
bun run prepare:tls      # generates a throwaway CA, then pulls the mock image
bunx playwright test --project=mock-oidc-tls
```

`prepare:tls` is required before `mock-oidc-tls`: it runs `tests/mock-oidc-tls/gencerts.sh`,
which creates `tests/mock-oidc-tls/certificates/` (gitignored, regenerated per run). The
suite fails fast with an explanatory error if that directory is missing.

### `mock-oidc` — general behaviour

Plain HTTP against the mock IdP. Covers login/logout over both entrypoints, post-login
redirects, headers, authorization rules, external authentication, error pages, and PKCE.

### `mock-oidc-tls` — the custom-CA trust path

Covers `provider.cABundle` and `provider.cABundleFile`: the option pair that lets the
plugin trust an IdP whose certificate is signed by a CA that is in nobody's system trust
store. Nine cases, T1–T9:

- **T1/T2** — the correct bundle, as a file and as inline base64, must complete a real
  login. T2 asserts *equivalence* with T1 (same final status **and** the same authorize
  redirect target), not merely that it worked.
- **T3** — no bundle at all must fail with `x509: certificate signed by unknown
  authority`. This is what gives T1 meaning: without it, T1 could pass because the mock
  was reachable rather than because the bundle was honoured.
- **T4/T5/T6** — a valid but *wrong* CA, an *empty* `cABundleFile`, and a bundle file of
  *garbage* PEM. Each is distinguished from T3 by a log line: `Loaded CA bundle` proves
  the file was read and applied (wrong CA), `Failed to append CA bundle` proves it was
  read but unparseable (garbage).
- **T7/T8/T9** — config errors that make the plugin's `New()` fail: invalid base64
  inline bundle, nonexistent bundle path, both options set at once.

T7–T9 assert on the plugin's **log line** rather than an HTTP status, on purpose: a config
whose constructor errored never becomes a router, so whether Traefik answers 404 or 500
is an internal detail that is deliberately not pinned. The log line is deterministic.

The negative cases also poll the Traefik log with a bounded retry rather than sleeping,
because the plugin logs asynchronously relative to the HTTP response.

## Keycloak was removed, and why

The custom-CA path used to be covered by `tests/keycloak/`: a Keycloak container with a
postgres sidecar, a realm import, and a two-level 4096-bit RSA CA chain. It was the
slowest and most fragile thing in CI and was red on `main` for a long time — slow enough
that its CI job was gated behind `workflow_dispatch`/`main` and gave **no pull-request
signal at all** for the one feature only it covered.

`mock-oidc-tls` covers the same code path against an IdP the repo already depends on, boots
in ~3 seconds, and generates its certificates in ~0.15 s. So the coverage moved from
"red, and only on main" to "gating every PR". The Keycloak suite, its Playwright project,
its workflow job, its npm scripts and its `.dockerignore` entries are all gone.

## Known limitation: what no test here proves

Because mock-oauth2-server is now the only IdP in `e2e/`, and because it is deliberately
permissive, there are places where a real-provider regression would be **invisible to CI**.
This is a known and accepted limitation of the current suite, **not** a guarantee that the
behaviours work:

- **A provider that rejects a bad `client_secret`.** mock-oauth2-server does not check
  `client_secret` at all, so nothing in e2e proves the plugin sends the configured secret
  correctly or that a wrong one is rejected.
- **A provider that requires a PKCE verifier.** A *missing* verifier is silently accepted
  by the mock; only a *wrong* one is rejected. There is a positive PKCE test in the
  `mock-oidc` project that proves the plugin's S256 round trip works against a real OIDC
  implementation — but it does **not** prove a provider would reject a PKCE downgrade.
- **A provider that validates `redirect_uri`,** emits a `sid` claim for front-channel
  logout, or publishes `*_supported` discovery metadata. The mock does none of these.

Treating green CI as "the plugin works against a standards-compliant identity provider"
would be a misreading of what is measured. `docs/e2e-test-design.md` (Phase 3) carries the
same list with the reasoning and the source citations.
