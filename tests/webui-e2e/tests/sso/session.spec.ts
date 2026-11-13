// Copyright 2026 Versity Software
// This file is licensed under the Apache License, Version 2.0
// (the "License"); you may not use this file except in compliance
// with the License.  You may obtain a copy of the License at
//
//   http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing,
// software distributed under the License is distributed on an
// "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied.  See the License for the
// specific language governing permissions and limitations
// under the License.

// What happens as a single sign-on session nears its end: renewal with the
// provider's refresh token, or signing in again through the provider.

import { helloObject, seedBucket } from '../../src/data/buckets';
import { users } from '../../src/data/users';
import { expect, test } from '../../src/fixtures/sso';

const twoMinutes = 2 * 60_000;

test('renews in the background before the session ends', async ({ signInWithSSO, ssoSession, app, explorer }) => {
  await signInWithSSO(users.bob);
  const accessKey = await ssoSession.accessKey();
  const documentId = await app.documentId();

  await ssoSession.expireIn(twoMinutes);

  await expect.poll(() => ssoSession.accessKey()).not.toBe(accessKey);
  expect(await app.documentId(), 'the page reloaded').toBe(documentId);
  await expect(app.sessionBanner).toBeHidden();

  // The renewed credentials are the ones the next page signs with.
  await explorer.openBucket(seedBucket.name);
  await expect(explorer.objectRow(helloObject.key)).toBeVisible();
});

test('a disabled account cannot renew, and the WebUI says so', async ({
  signInWithSSO,
  idpAccounts,
  ssoSession,
  app,
}) => {
  await signInWithSSO(users.frank);
  await idpAccounts.disable(users.frank);

  await ssoSession.expireIn(twoMinutes);

  await expect(app.sessionBanner).toContainText('Session ends in 2 mins');
  await expect(app.signInAgainButton).toBeVisible();
});

test('a session that cannot renew signs in again when it ends, back to the same page', async ({
  signInWithSSO,
  ssoSession,
  loginPage,
  explorer,
  page,
}) => {
  await signInWithSSO(users.bob);
  await explorer.openBucket(seedBucket.name);
  const accessKey = await ssoSession.accessKey();
  await ssoSession.forgetRefreshToken();

  // The provider still knows the user, so it sends the tab straight back
  // without asking for a password.
  const callback = loginPage.waitForProviderCallback();
  await ssoSession.expireIn(-1_000);
  await callback;

  await expect(page).toHaveURL(explorer.url(seedBucket.name));
  await expect(explorer.objectRow(helloObject.key)).toBeVisible();
  expect(await ssoSession.accessKey()).not.toBe(accessKey);
});
