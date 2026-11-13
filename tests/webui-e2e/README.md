# WebUI end-to-end tests

These tests drive the WebUI in a real browser (Chromium, through
[Playwright](https://playwright.dev)). The WebUI runs against versitygw
processes built from this checkout. Today they cover single sign-on, and they
run against two real identity providers: Keycloak and authentik.

## Running them

You need Go, Node.js 22 or later, and Docker. Run everything from this
directory.

```sh
npm ci                               # once, and after package.json changes
npx playwright install chromium      # once per Playwright version
npm run idp:up                       # start Keycloak and authentik; leave them running
npm test                             # build versitygw, start it, run every test
```

The first `idp:up` takes a minute or two while authentik sets up its
database. After that the providers keep running between test runs. Stop them
with `npm run idp:down`. Their databases live in memory, so the next `idp:up`
starts from the files under `docker/` again.

Other ways to run:

```sh
npx playwright test --project sso-keycloak        # one identity provider
npx playwright test tests/sso/roles.spec.ts       # one file
npx playwright test -g "several roles"            # tests whose title matches
npm run test:ui                                   # interactive: pick, watch and rerun tests
npx playwright test --headed --debug -g "sign-out"
npm run report                                    # the HTML report of the last run
```

Each run builds versitygw with `go build`. To test a binary you already have,
set `VERSITYGW_BINARY=/path/to/versitygw`.

Everything listens on 127.0.0.1: versitygw on ports 26100–26121, and the
identity providers on 26180 and 26190.

## What runs

| Process | Ports | What it is |
|---|---|---|
| IAM service | 26100 | Standalone IAM: the accounts, the roles and the registered providers |
| keycloak gateway | S3 26110, WebUI 26111 | S3 gateway backed by the IAM service; its WebUI signs in with Keycloak |
| authentik gateway | S3 26120, WebUI 26121 | The same, signing in with authentik |
| Keycloak (Docker) | 26180 | The `versitygw` realm |
| authentik (Docker) | 26190 | The `versitygw` application |

The browser signs in at a provider. It trades the provider's ID token for
temporary credentials at the IAM service, then signs S3 requests with them.
The gateways check those credentials with the IAM service, and the IAM
service fetches the providers' signing keys to verify the tokens.

Before any test, the global setup does three things:

1. It checks that the identity providers are up.
2. It starts the processes listed in `src/topology.ts`: one standalone IAM
   service, plus one S3 gateway with a WebUI for each identity provider.
3. It provisions them. This registers both providers on the IAM service,
   creates the roles from `src/data/roles.ts`, and creates the seed bucket
   from `src/data/buckets.ts` on every gateway.

Every process logs to `logs/`. After the run, the setup stops the processes
and deletes their data.

A Playwright project is one gateway, so it is also one identity provider. The
`tests/sso` specs run once in the `sso-keycloak` project and once in the
`sso-authentik` project.

## Layout

```
docker/             the identity providers: compose file, Keycloak realm, authentik blueprint
src/
  config.ts         root credentials, account, region, paths
  topology.ts       the versitygw processes, and which WebUI uses which provider
  data/             test users, IAM roles, seed buckets
  idp/              one module per identity provider, behind identity-provider.ts
  aws/              AWS SDK clients and IAM policy documents
  environment/      global setup: build, start, provision and stop versitygw
  pages/            page objects for the WebUI
  fixtures/         what tests receive: webui.ts for every test, sso.ts adds the provider
tests/
  sso/              single sign-on specs, run once per identity provider
```

## Writing tests

- **Import `test` and `expect` from a fixtures module**, not from
  `@playwright/test`. Use `src/fixtures/sso.ts` for single sign-on tests and
  `src/fixtures/webui.ts` for anything else. The fixtures give each test page
  objects for the project's gateway (`loginPage`, `app`, `explorer`, and so
  on). The SSO fixtures add `signInWithSSO(user)` and the provider
  (`idp`, `idpLoginPage`, `idpAccounts`).
- **Put selectors in page objects**, never in specs. For WebUI elements, use
  their IDs: they are ours, and they don't change when the wording does. For
  the identity providers' pages, use roles and labels, which hold up better
  across their versions than CSS.
- **Assert with web-first assertions** (`await expect(locator).toBeVisible()`,
  `toHaveText`, `toHaveURL`, `expect.poll`), which retry until they time out.
  Don't use fixed sleeps.
- **Keep tests independent.** Every test gets a fresh browser context and may
  run in parallel with any other test. Write objects under the `keyPrefix`
  fixture. Never change the seed bucket's contents. A test that changes a
  user at the provider uses the user reserved for that (`frank`), through
  `idpAccounts`, which undoes the change after the test.
- **Reach into the WebUI's scripts only through `src/pages/sso-session.ts`.**
  The WebUI's scripts are internals, so this one class is the only place that
  depends on them. It exists for things a browser can't do quickly, such as
  making a 15-minute session end now.

### Adding a test user, role or bucket

Users exist at the identity providers. To add one, add it to *both*
`docker/keycloak/versitygw-realm.json` and `docker/authentik/versitygw.yaml`,
then to `src/data/users.ts`. Restart the providers to load the change:
`npm run idp:down && npm run idp:up`. Roles and buckets are created at setup,
so adding one to `src/data/` is enough.

### Adding an identity provider

1. Run it in `docker/compose.yml`, with a healthcheck that passes only once it
   serves the test client. Give it the same users, groups and `vgw_roles`
   claim as the other providers.
2. Write `src/idp/<name>.ts`, which implements `IdentityProvider`: its issuer,
   its sign-in page object and its admin API.
3. In `src/topology.ts`, add a gateway that signs in with it. Use a WebUI
   address that the provider allows as a redirect URI.

That's all: `playwright.config.ts` makes an `sso-<name>` project from the
gateway, so every SSO spec also runs against the new provider.

### Adding a test suite

For WebUI features other than single sign-on, add a folder under `tests/`.
Add a project for it in `playwright.config.ts`. If it needs a differently
configured gateway, add one to `src/topology.ts`. Put the page objects for any
new screens in `src/pages/`, and their fixtures in `src/fixtures/webui.ts`.

## CI

`.github/workflows/webui-e2e.yml` runs on every pull request. It starts the
providers, builds versitygw and runs `npm test` with `CI` set, which retries a
failed test once. Each run uploads an artifact named `webui-e2e-report`. It
holds the HTML report, a trace and screenshot for each failed test, and the
versitygw and identity provider logs. To step through a failure, open its
trace:

```sh
npx playwright show-trace path/to/trace.zip
```

## Looking around the identity providers

| | Address | Sign in as |
|---|---|---|
| Keycloak admin console | http://127.0.0.1:26180/admin | `admin` / `admin` |
| authentik admin interface | http://127.0.0.1:26190/if/admin/ | `akadmin` / `admin` |

The test users' passwords are their user names.
