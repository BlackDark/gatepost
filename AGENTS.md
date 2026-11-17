# gatepost

OIDC authentication for Traefik: a Yaegi plugin plus an ext_authz sidecar.

## Verify

- `mise run check`: builds, race-enabled tests, gofmt, vet, golangci-lint, govulncheck, and E2E TypeScript lint for both Go modules.
- Docker changes: run the ext_authz image build and smoke tests from `.github/workflows/testing.yaml` in CI.
- Run the Playwright E2E workflows after changing authentication behavior.

CI separates code checks from actionlint, zizmor, and strict Renovate validation. The required gate is `check`.

## Stack

Follows https://github.com/BlackDark/agent-presets/blob/main/stack/core.md.

Deviations:
- `vendor/` is committed. Do not run mutating dependency commands; CI verifies module integrity and unchanged manifests.
- The plugin's Go directive stays on the Traefik E2E compatibility line. The sidecar builder image moves independently.
- Playwright E2E remains a separate specialized workflow; `mise run check` covers its lint, not browser tests.

## Map

- `src/`: Traefik plugin and OIDC behavior.
- `cmd/gatepost-extauthz/`: independent Go module and sidecar image.
- `e2e/`: Bun, Biome, Playwright, and mock-provider fixtures.

## Git

- Conventional Commits, one topic per PR.
- Squash unless commits need separate review.
- Force-push only with `--force-with-lease` on own branches.

## Boundaries

- Tools come from `mise.toml`; no global installs.
- Do not publish images or create release tags from a local session.
