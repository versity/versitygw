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

// Which role a single sign-on session gets: the role claim offers the
// roles, and the role's trust policy has the last word.

import { roles } from '../../src/data/roles';
import { users } from '../../src/data/users';
import { expect, test } from '../../src/fixtures/sso';

test('a user with one role signs straight in', async ({ signInWithSSO, app, page }) => {
  await signInWithSSO(users.alice);

  await expect(page).toHaveURL(/\/dashboard\.html$/);
  await expect(app.accountMenu).toContainText(`SSO · ${roles.admins.name}`);
  await expect(app.accountMenu).toContainText(/Session ends \d/);
});

test('a user with several roles chooses one', async ({ attemptSignInWithSSO, loginPage, app }) => {
  await attemptSignInWithSSO(users.carol);

  await expect(loginPage.roleChoices).toHaveCount(2);
  await expect(loginPage.roleChoice(roles.admins)).toBeVisible();
  await expect(loginPage.roleChoice(roles.readers)).toBeVisible();

  await loginPage.chooseRole(roles.readers);
  await expect(app.accountMenu).toContainText(users.carol.email);
  await expect(app.accountMenu).toContainText(`SSO · ${roles.readers.name}`);
});

test('a user without a role is refused', async ({ attemptSignInWithSSO, loginPage }) => {
  await attemptSignInWithSSO(users.dave);

  await expect(loginPage.errorMessage).toHaveText('No role is assigned to your account. Ask your administrator.');
  await expect(loginPage.singleSignOnButton).toBeVisible();
});

test('a role whose trust policy leaves out the user is refused', async ({ attemptSignInWithSSO, loginPage }) => {
  await attemptSignInWithSSO(users.mallory);

  await expect(loginPage.errorMessage).toContainText(
    "Your sign-in was rejected: your account doesn't meet this role's conditions",
  );
  await expect(loginPage.singleSignOnButton).toBeVisible();
});
