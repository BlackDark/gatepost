import fs from 'node:fs';
import path from 'node:path';
import { expect, type Page, type Response, test } from '@playwright/test';
import * as dockerCompose from 'docker-compose';
import { configureTraefik } from '../../utils';

test.use({
  ignoreHTTPSErrors: true,
});

test.beforeAll('Starting keycloak', async () => {
  // Cold `keycloak start-dev` on a shared runner: augmented build, DB
  // migration and the master-realm import together realistically take minutes.
  // This budget must cover compose's --wait-timeout (420s below) PLUS the
  // 180s readiness wait that follows it - the two are sequential, so it has to
  // be their sum, not either one alone.
  test.setTimeout(900_000);
  process.env.NODE_TLS_REJECT_UNAUTHORIZED = '0';

  await configureTraefik(`
http:
  services:
    whoami:
      loadBalancer:
        servers:
          - url: http://whoami:80

  middlewares:
    oidc-auth:
      plugin:
        traefik-oidc-auth:
          logLevel: DEBUG
          secret: "0123456789abcdef0123456789abcdef"
          provider:
            url: "\${PROVIDER_URL_HTTP}"
            clientId: "\${CLIENT_ID}"
            clientSecret: "\${CLIENT_SECRET}"
            usePkce: false

  routers:
    whoami:
      entryPoints: ["web"]
      rule: "PathPrefix(\`/\`)"
      service: whoami
      middlewares: ["oidc-auth@file"]
    whoami-secure:
      entryPoints: ["websecure"]
      tls: {}
      rule: "PathPrefix(\`/\`)"
      service: whoami
      middlewares: ["oidc-auth@file"]
`);

  await dockerCompose.upAll({
    cwd: __dirname,
    log: true,
    // Compose's --wait blocks until every service is healthy. With the
    // healthchecks in docker-compose.yml that now means "keycloak answered
    // /health/ready", not merely "the container process is alive". The
    // timeout must exceed keycloak's own health budget (start_period 90s +
    // 36 * interval 5s ~= 270s) or compose gives up while keycloak is still
    // legitimately importing.
    commandOptions: ['--wait', '--wait-timeout', '420'],
  });

  // Belt and braces. `docker compose up --wait` guarantees keycloak's container
  // is healthy; it does not guarantee Traefik has finished loading the plugin
  // config we just wrote, nor that the plugin's own OIDC discovery call against
  // keycloak succeeds. Poll through Traefik until the plugin really redirects
  // to keycloak before the first assertion runs.
  await waitForOidcDiscovery('beforeAll');
});

// Readiness probe. The plugin never serves a discovery document to clients:
// it runs EnsureOidcDiscovery() on every request and then 302s to the
// provider's authorization endpoint. So the observable that actually proves
// "keycloak answered OIDC discovery" is that 302 plus its Location header -
// not a 200 with a discovery body, which would never arrive.
//
// The 9080 (http) URL is probed in beforeAll, where the config points the
// plugin at keycloak's plain-HTTP listener. The 9443 (https) URLs are probed
// after each in-test config rewrite, where the plugin uses cABundleFile /
// cABundle against keycloak's HTTPS listener - so those waits prove the
// custom-CA path loaded, not just that Traefik is up.
const READINESS_PATH = '/protocol/openid-connect/auth';

async function waitForOidcDiscovery(stage: string, url = 'http://localhost:9080/'): Promise<void> {
  const deadline = Date.now() + 180_000;
  let lastError = 'never attempted';
  let attempts = 0;

  while (Date.now() < deadline) {
    attempts++;
    try {
      const res = await fetch(url, {
        redirect: 'manual',
        signal: AbortSignal.timeout(5_000),
      });
      const location = res.headers.get('location') ?? '';
      if (res.status >= 300 && res.status < 400 && location.includes(READINESS_PATH)) {
        return;
      }
      lastError =
        `HTTP ${res.status} ${res.statusText}` +
        (location ? ` (Location: ${location.slice(0, 200)})` : ' (no Location header)');
    } catch (err) {
      lastError = err instanceof Error ? `${err.name}: ${err.message}` : String(err);
    }
    await new Promise((r) => setTimeout(r, 1_000));
  }

  // Include the container state in the message: on CI the job log is the only
  // artefact, so the failure has to explain itself here.
  throw new Error(
    [
      `Timed out after 180s (${attempts} attempts) waiting for ${url} to`,
      `redirect to the keycloak authorization endpoint during ${stage}.`,
      `Last response: ${lastError}`,
      '',
      'Container state (docker compose ps -a):',
      await collectDiagnostics(),
    ].join('\n'),
  );
}

// biome-ignore lint/correctness/noEmptyPattern: Playwright fixture API
test.afterEach('Traefik logs on test failure', async ({}, testInfo) => {
  if (testInfo.status !== testInfo.expectedStatus) {
    console.log(`${testInfo.title} failed, here are Traefik logs:`);
    console.log(await dockerCompose.logs('traefik', { cwd: __dirname }));
    console.log(await dockerCompose.logs('keycloak', { cwd: __dirname }));
    // The plain log stream usually does not show *why* a container died
    // (OOM-kill, exit code, failed healthcheck). `docker compose ps -a` carries
    // the exit code and health status, so print it too.
    console.log(`${testInfo.title} failed, here is the container state:`);
    console.log(await collectDiagnostics());
  }
});

/**
 * `docker compose ps -a` for this stack, as text. Never throws: this is called
 * from failure paths, and a diagnostics helper that itself throws would mask
 * the error we are trying to report.
 */
async function collectDiagnostics(): Promise<string> {
  try {
    const result = await dockerCompose.execCompose('ps', ['-a'], { cwd: __dirname });
    const out = `${result.out}${result.err}`.trim();
    return out.length > 0 ? out : '(docker compose ps -a produced no output)';
  } catch (err) {
    const detail = err && typeof err === 'object' ? JSON.stringify(err) : String(err);
    return `(failed to run "docker compose ps -a": ${detail})`;
  }
}

test.afterAll('Stopping keycloak', async () => {
  await dockerCompose.downAll({
    cwd: __dirname,
    log: true,
  });
});

test('login at provider via self signed certificate from file', async ({ page }) => {
  // Covers the readiness wait below on top of the default 60s per-test budget.
  test.setTimeout(240_000);

  await configureTraefik(`
http:
  services:
    whoami:
      loadBalancer:
        servers:
          - url: http://whoami:80

  middlewares:
    oidc-auth:
      plugin:
        traefik-oidc-auth:
          logLevel: DEBUG
          secret: "0123456789abcdef0123456789abcdef"
          provider:
            url: "\${PROVIDER_URL_HTTPS}"
            cABundleFile: "/certificates/bundle/ca_bundle.pem"
            clientId: "\${CLIENT_ID}"
            clientSecret: "\${CLIENT_SECRET}"
            usePkce: false

  routers:
    whoami:
      entryPoints: ["web"]
      rule: "PathPrefix(\`/\`)"
      service: whoami
      middlewares: ["oidc-auth@file"]
    whoami-secure:
      entryPoints: ["websecure"]
      tls: {}
      rule: "PathPrefix(\`/\`)"
      service: whoami
      middlewares: ["oidc-auth@file"]
`);

  // Confirms the rewrite was picked up AND that the cABundleFile let the plugin
  // complete discovery against keycloak's HTTPS listener. Without this the
  // test would race Traefik's file-provider reload and fail on page.goto.
  await waitForOidcDiscovery('cABundleFile test', 'https://localhost:9443/');

  await expectGotoOkay(page, 'https://localhost:9443');
  const response = await login(page, 'admin', 'admin', 'https://localhost:9443');
  expect(response.status()).toBe(200);
});

test('login at provider via self signed inline certificate', async ({ page }) => {
  test.setTimeout(240_000);

  const certBundle = fs.readFileSync(path.join(__dirname, './certificates/bundle/ca_bundle.pem'));
  const base64CertBundle = certBundle.toString('base64');

  await configureTraefik(`
http:
  services:
    whoami:
      loadBalancer:
        servers:
          - url: http://whoami:80

  middlewares:
    oidc-auth:
      plugin:
        traefik-oidc-auth:
          logLevel: DEBUG
          secret: "0123456789abcdef0123456789abcdef"
          provider:
            url: "\${PROVIDER_URL_HTTPS}"
            cABundle: "base64:${base64CertBundle}"
            clientId: "\${CLIENT_ID}"
            clientSecret: "\${CLIENT_SECRET}"
            usePkce: false

  routers:
    whoami:
      entryPoints: ["web"]
      rule: "PathPrefix(\`/\`)"
      service: whoami
      middlewares: ["oidc-auth@file"]
    whoami-secure:
      entryPoints: ["websecure"]
      tls: {}
      rule: "PathPrefix(\`/\`)"
      service: whoami
      middlewares: ["oidc-auth@file"]
`);

  // Same reasoning as the cABundleFile test above, for the inline cABundle.
  await waitForOidcDiscovery('inline cABundle test', 'https://localhost:9443/');

  await expectGotoOkay(page, 'https://localhost:9443');
  const response = await login(page, 'admin', 'admin', 'https://localhost:9443');
  expect(response.status()).toBe(200);
});

async function login(
  page: Page,
  username: string,
  password: string,
  waitForUrl: string,
): Promise<Response> {
  await page.locator('#username').fill(username);
  await page.locator('#password').fill(password);
  const responsePromise = page.waitForResponse(waitForUrl);
  await page.locator('#kc-login').click();
  return responsePromise;
}

async function expectGotoOkay(page: Page, url: string) {
  const response = await page.goto(url);
  expect(response?.status()).toBe(200);
}
