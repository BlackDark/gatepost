/**
 * Coverage for provider.cABundle / provider.cABundleFile: the custom-CA trust
 * path the plugin's server-to-server TLS client uses to reach the identity
 * provider.
 *
 * This suite replaces the deleted keycloak stack. It is the same class of test
 * (an IdP whose certificate is signed by a CA that is in no system trust store)
 * against mock-oauth2-server behind an nginx TLS terminator, so it boots in
 * seconds instead of minutes and can gate pull requests.
 *
 * TLS is terminated by nginx rather than by the mock itself. mock-oauth2-server
 * can serve HTTPS, but when its keystore config is not picked up it silently
 * falls back to a self-signed certificate generated at boot, whose CA nothing
 * outside can know - and the suite then fails with "x509: certificate signed by
 * unknown authority" while looking for a bug in the plugin. The mock's plain HTTP
 * mode is already proven by the mock-oidc project, so only the TLS leg moved.
 */

// Set at module scope, not in beforeAll: Playwright loads the spec file before
// any fixture runs, and this variable is read per TLS connection by Node's
// fetch. Both matter - the /isalive liveness guard and the readiness poll below
// open HTTPS connections to a self-signed listener, and `ignoreHTTPSErrors`
// only covers the browser, not Node.
process.env.NODE_TLS_REJECT_UNAUTHORIZED = '0';

import { X509Certificate } from 'node:crypto';
import fs from 'node:fs';
import https from 'node:https';
import path from 'node:path';
import { expect, type Page, type Response, test } from '@playwright/test';
import * as dockerCompose from 'docker-compose';
import { configureTraefik } from '../../utils';

const HTTP_URL = 'http://localhost:9180';
const HTTPS_URL = 'https://localhost:9543';
const IDP_HEALTH_URL = 'https://127.0.0.1:8443/isalive';
// The authorization endpoint the plugin must redirect to. Asserting on this
// rather than "we got some redirect" is what makes T1 meaningful.
const AUTHORIZE_PATH = '/default/authorize';
const PLUGIN_SECRET = '0123456789abcdef0123456789abcdef';
const CERT_DIR = path.join(__dirname, 'certificates');

const X509_UNKNOWN_AUTHORITY = 'x509: certificate signed by unknown authority';
// Must match the -subj CN in gencerts.sh.
const CA_COMMON_NAME = 'Mock OIDC Test CA';

/**
 * T2's equivalence check compares the two config forms against EACH OTHER, and
 * both targets are measured inside T2 rather than T1's being borrowed from
 * module state.
 *
 * That is not tidiness. Playwright re-runs a failed test in a FRESH worker in CI
 * (`retries: process.env.CI ? 1 : 0`), and every case in this file must be
 * runnable on its own with `-g`. A value captured by T1 is therefore unreliable
 * exactly where it matters most - on a retry, and on a single-test run - and
 * would surface as a confusing "expected '' to equal ..." rather than as a real
 * signal. Re-measuring the file-based form costs one extra config write.
 */

// Every negative case asserts on a log line the plugin emits. Traefik's log
// stream is append-only and shared by all tests in this file, so an assertion
// that scans the whole stream can be satisfied by a line an EARLIER test wrote -
// which would turn a real regression into a silent pass. Each negative case
// therefore takes a mark (the current length of the stream) before rewriting
// the config and only searches past it.
async function traefikLogMark(): Promise<number> {
  return (await traefikLogs()).length;
}

/**
 * Poll for `needle` in the traefik log stream past `mark`.
 *
 * The plugin logs asynchronously relative to the HTTP response: for the
 * New()-failure cases (T7-T9) the log line is written while Traefik is parsing
 * the config, which can finish after the request that raced it. A fixed sleep
 * would be either too short (flake) or too long (slow suite), so this polls
 * with a bounded deadline instead.
 */
async function waitForTraefikLog(
  mark: number,
  needle: string,
  timeoutMs = 15_000,
): Promise<string> {
  const deadline = Date.now() + timeoutMs;
  let tail = '';
  while (Date.now() < deadline) {
    tail = (await traefikLogs()).slice(mark);
    if (tail.includes(needle)) {
      return tail;
    }
    await new Promise((r) => setTimeout(r, 250));
  }
  throw new Error(
    `Timed out after ${timeoutMs}ms waiting for traefik to log ${JSON.stringify(needle)}.\n` +
      `--- traefik log since mark ---\n${tail.slice(-4000)}`,
  );
}

/**
 * dockerCompose.logs() resolves to an IDockerComposeResult, not a string -
 * `{ exitCode, out, err }`. Both streams are concatenated because docker compose
 * interleaves a service's stderr into err and the plugin writes to stdout, so
 * searching only one of them would miss lines.
 */
async function traefikLogs(): Promise<string> {
  try {
    const result = await dockerCompose.logs('traefik', { cwd: __dirname });
    return `${result.out}${result.err}`;
  } catch (err) {
    // A diagnostics helper that throws would mask the failure being reported.
    return `(failed to read traefik logs: ${String(err)})`;
  }
}

/**
 * A valid Traefik HTTP config whose only variable is the provider block. The
 * default (no CA bundle) is the negative baseline, T3.
 */
function oidcConfig(providerExtra = ''): string {
  return `
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
          secret: "${PLUGIN_SECRET}"
          provider:
            url: "\${PROVIDER_URL_HTTPS}"
            clientId: "\${CLIENT_ID}"
            clientSecret: "\${CLIENT_SECRET}"
            usePkce: false
${providerExtra}

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
`;
}

/**
 * Write a config and wait until Traefik has actually applied it.
 *
 * `wait: false` is required here for a reason that is easy to get wrong:
 * configureTraefik's default wait loop throws "Traefik config not ready" when
 * the deadline passes, which is correct for a config Traefik should accept but
 * is exactly backwards for T7-T9, where the plugin rejects the config in New()
 * and Traefik is never going to apply it. For those cases the readiness signal
 * is the plugin's own error log (see expectPluginRejected), not the router
 * list.
 *
 * It also sidesteps utils.ts polling Traefik's API on its hardcoded
 * localhost:8080, which is the OTHER suite's dashboard - this stack publishes
 * its API on 8180.
 */
async function writeConfig(yaml: string): Promise<void> {
  await configureTraefik(yaml, { file: '.http-tls.yml', wait: false });
}

/**
 * Readiness for a config that Traefik is expected to accept.
 *
 * The plugin never serves a discovery document to clients, so the observable
 * that proves "the plugin loaded this CA and completed OIDC discovery" is a 302
 * whose Location is the IdP's authorization endpoint. For the cABundleFile /
 * cABundle cases that also means the custom-CA path actually loaded - a
 * Traefik that merely came up would return a 500 here instead.
 */
async function waitForAuthorizeRedirect(url = `${HTTP_URL}/`, timeoutMs = 30_000): Promise<string> {
  const deadline = Date.now() + timeoutMs;
  let last = 'never attempted';
  while (Date.now() < deadline) {
    try {
      // Accept: text/html matters and is easy to miss. The default
      // unauthenticatedBehavior is "Auto", which content-negotiates: a browser
      // asking for HTML gets redirected to the IdP, anything else gets a bare
      // 401. Node's fetch sends `Accept: */*`, so without this header the plugin
      // correctly answers 401 and this helper waits forever for a redirect that
      // this client is not entitled to. Asking the way a browser asks is also
      // the more honest assertion - it is the same request the test's own
      // page.goto below will make.
      const res = await fetch(url, {
        redirect: 'manual',
        signal: AbortSignal.timeout(5_000),
        headers: { accept: 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8' },
      });
      const location = res.headers.get('location') ?? '';
      if (res.status >= 300 && res.status < 400 && location.includes(AUTHORIZE_PATH)) {
        return location;
      }
      last = `HTTP ${res.status} ${res.statusText}${location ? ` -> ${location}` : ' (no Location)'}`;
    } catch (err) {
      last = err instanceof Error ? `${err.name}: ${err.message}` : String(err);
    }
    await new Promise((r) => setTimeout(r, 500));
  }
  throw new Error(
    `Timed out after ${timeoutMs}ms waiting for ${url} to redirect to the IdP authorize endpoint.\n` +
      `Last response: ${last}\n--- traefik log tail ---\n${(await traefikLogs()).slice(-4000)}`,
  );
}

/**
 * Normalize an authorize redirect for comparison between two runs.
 *
 * `state` and `nonce` are per-request random by design, so they are dropped;
 * everything else (origin, endpoint, client_id, scope, response_type,
 * redirect_uri) must match. That is what turns T2 from "the inline bundle also
 * worked" into "the inline bundle produced identical plugin behaviour", which is
 * the property that actually matters: a wrong inline bundle that happened to
 * still verify would otherwise pass.
 */
function authorizeTarget(location: string): string {
  const u = new URL(location);
  u.searchParams.delete('state');
  u.searchParams.delete('nonce');
  u.searchParams.sort();
  return `${u.origin}${u.pathname}?${u.searchParams.toString()}`;
}

/**
 * Liveness guard for the negative cases.
 *
 * Without this, a dead or still-booting IdP fails the TLS handshake too, and
 * every negative test would pass for a completely wrong reason. Asserting the
 * IdP answers /isalive first means an x509 rejection can only come from the
 * bundle under test.
 */
async function expectIdpAlive(): Promise<void> {
  const res = await fetch(IDP_HEALTH_URL, { signal: AbortSignal.timeout(5_000) });
  expect(res.ok, `${IDP_HEALTH_URL} did not answer: HTTP ${res.status}`).toBeTruthy();
}

/**
 * A config whose plugin New() returns an error never becomes a router, so the
 * HTTP status Traefik returns is an internal detail (404 or 500 depending on
 * Traefik's internals) and asserting a specific one would encode an
 * implementation detail we have deliberately not verified - and would break for
 * the right behaviour whenever Traefik changes it.
 *
 * The deterministic signal is the plugin's own log line: it is written while
 * Traefik parses the config, independent of how Traefik then routes. So assert
 * on the log, and assert only that the request did not succeed.
 */
async function expectPluginRejected(mark: number, needle: string): Promise<void> {
  await waitForTraefikLog(mark, needle);
  const res = await fetch(`${HTTP_URL}/`, { redirect: 'manual' });
  expect(res.status, `request unexpectedly succeeded (200) despite: ${needle}`).not.toBe(200);
}

/** A request through the plugin, returning the status Traefik answered with. */
async function statusThroughPlugin(): Promise<number> {
  const res = await fetch(`${HTTP_URL}/`, { redirect: 'manual' });
  return res.status;
}

/**
 * Wait until a request through the plugin stops being answered by the PREVIOUS
 * config.
 *
 * Traefik picks up a rewritten file-provider config asynchronously, so the
 * first request after writeConfig can still be served by the config the last
 * test left behind - which for every negative case is a WORKING one that
 * answers 302. Asserting immediately would flake on a loaded runner. Polling
 * for "no longer a redirect to the IdP" is the deterministic signal that the new
 * config is live, and it is bounded so a genuine failure still surfaces.
 *
 * Note the ordering consequence for the x509 cases: this helper is what
 * generates the x509 log line (discovery runs per request), so the request must
 * precede the log assertion.
 */
async function waitForFailedRequest(timeoutMs = 30_000): Promise<number> {
  const deadline = Date.now() + timeoutMs;
  let last = 0;
  while (Date.now() < deadline) {
    last = await statusThroughPlugin();
    if (last !== 302) {
      return last;
    }
    await new Promise((r) => setTimeout(r, 500));
  }
  throw new Error(
    `Timed out after ${timeoutMs}ms: ${HTTP_URL}/ still redirects to the IdP, so the new ` +
      `Traefik config never took effect (last status ${last}).\n` +
      `--- traefik log tail ---\n${(await traefikLogs()).slice(-4000)}`,
  );
}

/**
 * Prove the TLS terminator is actually serving the certificate gencerts.sh made,
 * by reading the peer certificate off the wire and checking its issuer.
 *
 * This exists because "x509: certificate signed by unknown authority" has three
 * indistinguishable causes - the terminator serves a different certificate, the
 * plugin never received the bundle, or the plugin received it and still cannot
 * build a path - and guessing between them from the failure message alone wasted
 * two CI runs. It is an assertion, not a log line: if this passes and the login
 * still fails, the fault is unambiguously on the plugin-config side.
 */
async function peerCertificate(): Promise<X509Certificate> {
  return new Promise((resolve, reject) => {
    const req = https.request(
      { host: '127.0.0.1', port: 8443, path: '/isalive', rejectUnauthorized: false },
      (res) => {
        res.resume();
        const peer = res.socket.getPeerCertificate();
        if (!peer || Object.keys(peer).length === 0) {
          reject(new Error('the TLS terminator presented no certificate'));
          return;
        }
        resolve(peer);
      },
    );
    req.on('error', reject);
    req.end();
  });
}

/**
 * Prove the TLS terminator is serving the exact leaf gencerts.sh signed, and
 * that a client trusting our CA can complete the plugin's discovery call.
 *
 * This exists because "x509: certificate signed by unknown authority" has three
 * indistinguishable causes - the terminator serves a different certificate, the
 * pool we hand the plugin cannot verify that certificate, or the plugin is not
 * using the pool we think it is - and choosing between them from the failure
 * message alone already cost two CI runs. Comparing fingerprints settles the
 * first question outright; performing the discovery request with only our CA
 * trusted settles the second. If both pass and the plugin still fails, the
 * fault is unambiguously inside the plugin's TLS setup rather than in the
 * fixture.
 */
async function expectServedCertFromOurCa(): Promise<void> {
  const expected = new X509Certificate(fs.readFileSync(path.join(CERT_DIR, 'website.pem')));
  const peer = await peerCertificate();

  expect(
    peer.fingerprint256,
    `the TLS terminator served a different certificate than certificates/website.pem ` +
      `(served ${peer.fingerprint256}, generated ${expected.fingerprint256}). Either the ` +
      `certificates directory is stale for this run, or something else is bound to port 8443.`,
  ).toBe(expected.fingerprint256);

  expect((peer.issuer as { CN?: string } | undefined)?.CN).toBe(CA_COMMON_NAME);

  // The discovery call the plugin makes, with nothing but our CA trusted - the
  // same trust decision cABundle makes on the plugin's behalf.
  const caPem = fs.readFileSync(path.join(CERT_DIR, 'ca.pem'));
  const discovery = await new Promise<number>((resolve) => {
    const req = https.request(
      {
        host: '127.0.0.1',
        port: 8443,
        path: '/default/.well-known/openid-configuration',
        ca: [caPem],
        servername: 'localhost',
      },
      (res) => {
        res.resume();
        resolve(res.statusCode ?? 0);
      },
    );
    req.on('error', () => resolve(-1));
    req.end();
  });
  expect(
    discovery,
    `a client trusting only our CA could not complete the discovery request (status ${discovery}). ` +
      `The certificate chain itself is therefore broken, independent of the plugin.`,
  ).toBe(200);
}

async function login(page: Page, username: string, password: string, waitForUrl: string) {
  await page.locator('#username').waitFor({ state: 'visible' });
  await page.locator('#username').fill(username);
  await page.locator('#password').fill(password);
  const responsePromise: Promise<Response> = page.waitForResponse(
    (r) => r.status() === 200 && r.url().startsWith(waitForUrl),
  );
  await page.locator('#kc-login').click();
  return responsePromise;
}

test.use({ ignoreHTTPSErrors: true });

test.beforeAll('Starting mock-oidc-tls stack', async () => {
  test.setTimeout(180_000);

  if (!fs.existsSync(path.join(CERT_DIR, 'ca.pem'))) {
    throw new Error(
      `${CERT_DIR} is missing. Run "bun run prepare:tls" (which runs ./gencerts.sh) before this suite.`,
    );
  }

  await writeConfig(oidcConfig());

  await dockerCompose.upAll({
    cwd: __dirname,
    log: true,
    // The mock has a healthcheck and boots in ~3s, so this is generous rather
    // than tuned. It exists to fail fast with a readable message rather than to
    // paper over a slow runner.
    commandOptions: ['--wait', '--wait-timeout', '60'],
  });
});

test.beforeEach(async ({ context }) => {
  await context.clearCookies();
});

// biome-ignore lint/correctness/noEmptyPattern: Playwright fixture API
test.afterEach('Traefik and mock IdP logs on failure', async ({}, testInfo) => {
  if (testInfo.status !== testInfo.expectedStatus) {
    console.log(`${testInfo.title} failed, here are Traefik logs:`);
    console.log(await traefikLogs());
    console.log(`${testInfo.title} failed, here are mock-oauth2-server logs:`);
    try {
      const mockLogs = await dockerCompose.logs('mock-oauth2-server', { cwd: __dirname });
      console.log(`${mockLogs.out}${mockLogs.err}`);
    } catch {
      console.log('(mock-oauth2-server logs unavailable)');
    }
  }
});

test.afterAll('Stopping mock-oidc-tls stack', async () => {
  await dockerCompose.downAll({ cwd: __dirname, log: true });
});

test('T1 cABundleFile with the CA that signed the IdP cert completes a login', async ({ page }) => {
  // Pin both halves of the contract before the login: the terminator must serve
  // our CA's leaf, and the plugin must report that it loaded our CA file. If
  // either is false the login below cannot succeed, and saying which one is the
  // difference between a five-second fix and a guessing loop.
  await expectServedCertFromOurCa();

  const mark = await traefikLogMark();
  await writeConfig(
    oidcConfig(`
            cABundleFile: "/certificates/ca.pem"`),
  );

  // The plugin logs this at DEBUG once it has read and appended the CA. Its
  // absence, with a successful TLS-terminator check above, means the option is
  // not reaching the plugin at all - which is a different bug from the option
  // being present and the chain still failing.
  await waitForTraefikLog(mark, 'Loaded CA bundle from /certificates/ca.pem');

  // Proves both that Traefik applied the rewrite and that cABundleFile let the
  // plugin finish discovery against the mock's HTTPS listener.
  await waitForAuthorizeRedirect();

  const goto = await page.goto(HTTPS_URL);
  expect(goto?.status()).toBe(200);
  const response = await login(page, 'admin', 'admin', HTTPS_URL);
  expect(response.status()).toBe(200);

  // The bundle must actually have been consumed, not merely tolerated.
  await waitForTraefikLog(mark, 'Loaded CA bundle');
});

test('T2 inline base64 cABundle behaves identically to cABundleFile', async ({ page }) => {
  // Equivalence with the file-based form is the actual assertion, not "it
  // worked". A bundle that was truncated or mis-encoded could still produce a
  // 200 here by accident, and a status code cannot see a behaviour difference
  // between the two config forms - the authorize redirect the plugin emitted
  // can. So the cABundleFile form is measured here too and the two targets are
  // compared directly.
  // Write BOTH forms here rather than inheriting one from the ambient config.
  // Measuring the file form from whatever config happens to be loaded makes this
  // test order-dependent: run on its own with -g, or after a failed T1, the
  // "file" measurement is really measuring a config with no CA bundle at all and
  // the equivalence assertion compares two failures.
  await writeConfig(
    oidcConfig(`
            cABundleFile: "/certificates/ca.pem"`),
  );
  const fileTarget = authorizeTarget(await waitForAuthorizeRedirect());

  const bundle = fs.readFileSync(path.join(CERT_DIR, 'ca.pem')).toString('base64');
  await writeConfig(
    oidcConfig(`
            cABundle: "base64:${bundle}"`),
  );

  const inlineTarget = authorizeTarget(await waitForAuthorizeRedirect());

  const goto = await page.goto(HTTPS_URL);
  expect(goto?.status()).toBe(200);
  const response = await login(page, 'admin', 'admin', HTTPS_URL);
  expect(response.status()).toBe(200);

  // state and nonce are dropped by authorizeTarget as per-request noise;
  // everything else must match exactly.
  expect(inlineTarget).toBe(fileTarget);
  // Guard against comparing two empties, which would pass vacuously.
  expect(inlineTarget).toContain(AUTHORIZE_PATH);
});

test('T3 no CA bundle is rejected as an unknown authority', async ({ page }) => {
  await expectIdpAlive();

  const mark = await traefikLogMark();
  await writeConfig(oidcConfig());

  // The request has to come BEFORE the log wait, and it has to be waited on:
  // the x509 rejection is produced by OIDC discovery, which this plugin only
  // runs on a request, so nothing logs it at config-load time.
  const status = await waitForFailedRequest();

  // This is the case that gives T1 meaning: without a bundle the very same
  // IdP is unreachable, so T1's success is attributable to the bundle and not
  // to the mock simply speaking HTTP.
  expect(status).toBe(500);
  await waitForTraefikLog(mark, X509_UNKNOWN_AUTHORITY);
  expect((await page.goto(HTTPS_URL))?.status()).toBe(500);
});

test('T4 a valid but unrelated CA bundle still fails, and is proved to have loaded', async () => {
  await expectIdpAlive();

  const mark = await traefikLogMark();
  await writeConfig(
    oidcConfig(`
            cABundleFile: "/certificates/other_ca.pem"`),
  );

  // "Loaded CA bundle" plus the x509 error is what separates a WRONG bundle
  // from NO bundle (T3): it shows the file was read and appended to the trust
  // pool, and the failure came from verification rather than from the plugin
  // never seeing a bundle at all. Without the first assertion, T4 would be a
  // copy of T3 that proves nothing new.
  //
  // Request first: the x509 line only exists once discovery has actually run.
  const status = await waitForFailedRequest();
  await waitForTraefikLog(mark, 'Loaded CA bundle');
  await waitForTraefikLog(mark, X509_UNKNOWN_AUTHORITY);

  expect(status).toBe(500);
});

test('T5 an empty cABundleFile is treated as unset', async () => {
  await expectIdpAlive();

  const mark = await traefikLogMark();
  await writeConfig(
    oidcConfig(`
            cABundleFile: ""`),
  );

  // Same observable as T3, and that is the point: an empty string must not be
  // handed to os.ReadFile as a path. The negative assertion is what makes that
  // claim - without it, "the same x509 error" would be equally consistent with
  // ReadFile having been called on "" and failed.
  const status = await waitForFailedRequest();
  await waitForTraefikLog(mark, X509_UNKNOWN_AUTHORITY);
  const tail = (await traefikLogs()).slice(mark);
  expect(tail).not.toContain('Failed to load CA bundle');

  expect(status).toBe(500);
});

test('T6 a bundle file containing garbage PEM is warned about and then fails TLS', async () => {
  await expectIdpAlive();

  // Written here rather than in gencerts.sh so the fixture lives next to the
  // one test that needs it. The /certificates bind mount is read-only inside
  // the container but this is a host-side write, and the mount is a live bind,
  // so Traefik sees the file immediately.
  const garbage = path.join(CERT_DIR, 'garbage.pem');
  fs.writeFileSync(garbage, 'this is not a PEM certificate\n');

  const mark = await traefikLogMark();
  await writeConfig(
    oidcConfig(`
            cABundleFile: "/certificates/garbage.pem"`),
  );

  // This WARN is the ONLY thing that separates T6 from T3. Both end in the same
  // x509 failure, because a bundle that cannot be parsed leaves the trust pool
  // exactly as it was. So if this assertion is dropped, T6 silently degrades
  // into a duplicate of T3 and the "loaded a file, could not parse it" branch
  // loses its only coverage.
  const status = await waitForFailedRequest();
  await waitForTraefikLog(mark, 'Failed to append CA bundle');
  await waitForTraefikLog(mark, X509_UNKNOWN_AUTHORITY);

  expect(status).toBe(500);
  // Best-effort cleanup; gencerts.sh rm -rf's the whole directory anyway, so a
  // leak here cannot poison a later run.
  fs.rmSync(garbage, { force: true });
});

test('T7 an inline cABundle with invalid base64 fails plugin construction', async () => {
  await expectIdpAlive();

  const mark = await traefikLogMark();
  await writeConfig(
    oidcConfig(`
            cABundle: "base64:!!!not-base64!!!"`),
  );

  // Asserted on the log rather than on a status code on purpose - see
  // expectPluginRejected for why the exact status is not a stable contract.
  await expectPluginRejected(mark, 'Failed to base64-decode the inline CA bundle');
});

test('T8 a cABundleFile pointing at a nonexistent path fails plugin construction', async () => {
  await expectIdpAlive();

  const mark = await traefikLogMark();
  await writeConfig(
    oidcConfig(`
            cABundleFile: "/certificates/does-not-exist.pem"`),
  );

  await expectPluginRejected(mark, 'Failed to load CA bundle');
});

test('T9 setting both cABundle and cABundleFile fails plugin construction', async () => {
  await expectIdpAlive();

  const bundle = fs.readFileSync(path.join(CERT_DIR, 'ca.pem')).toString('base64');

  const mark = await traefikLogMark();
  await writeConfig(
    oidcConfig(`
            cABundle: "base64:${bundle}"
            cABundleFile: "/certificates/ca.pem"`),
  );

  // Capital "Y": that is the plugin's own logger.Log line in src/config.go. Do
  // not "correct" it to lowercase to match the error string New() returns - the
  // two differ in case and only the logged form is guaranteed to be emitted
  // before the constructor gives up.
  await expectPluginRejected(mark, 'You can only use an inline CABundle OR CABundleFile');
});
