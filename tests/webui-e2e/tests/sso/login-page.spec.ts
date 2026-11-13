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

import { rootCredentials } from '../../src/config';
import { expect, test } from '../../src/fixtures/sso';

test('offers single sign-on above the access-key form', async ({ loginPage, idp }) => {
  await loginPage.open();

  await expect(loginPage.singleSignOnButton).toHaveText(idp.signInLabel);
  await expect(loginPage.accessKeyDivider).toBeVisible();
  await expect(loginPage.accessKeyField).toBeVisible();
});

test('still signs in with access keys', async ({ loginPage, app }) => {
  await loginPage.open();
  await loginPage.signInWithAccessKeys(rootCredentials.accessKeyId, rootCredentials.secretAccessKey);

  await expect(app.accountMenu).toContainText(rootCredentials.accessKeyId);
  await expect(app.accountMenu).not.toContainText('SSO');
});
