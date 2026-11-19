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

// Fixtures for single sign-on tests, on top of the WebUI ones. They run
// against the identity provider of the project's gateway.

import type { TestUser } from '../data/users';
import type { IdentityProvider, IdpLoginPage } from '../idp/identity-provider';
import { SSOSession } from '../pages/sso-session';
import { expect, test as webuiTest } from './webui';

/** Changes test accounts at the provider; every change is undone after the test. */
export interface IdpAccounts {
  disable(user: TestUser): Promise<void>;
}

interface SSOWorkerFixtures {
  /** The identity provider the project's gateway signs in with. */
  idp: IdentityProvider;
}

export interface SSOFixtures {
  /** The provider's sign-in page, in the test's tab. */
  idpLoginPage: IdpLoginPage;
  idpAccounts: IdpAccounts;
  ssoSession: SSOSession;
  /**
   * Opens the WebUI login page, clicks the single sign-on button and signs
   * in at the provider. Stops there, wherever the WebUI goes next.
   */
  attemptSignInWithSSO: (user: TestUser) => Promise<void>;
  /** Signs in with single sign-on and waits until the WebUI shows the user. */
  signInWithSSO: (user: TestUser) => Promise<void>;
}

export const test = webuiTest.extend<SSOFixtures, SSOWorkerFixtures>({
  idp: [
    async ({ gateway }, use) => {
      if (!gateway.sso) throw new Error(`the ${gateway.name} gateway has no single sign-on`);
      await use(gateway.sso);
    },
    { scope: 'worker' },
  ],

  idpLoginPage: async ({ page, idp }, use) => {
    await use(idp.loginPage(page));
  },
  idpAccounts: async ({ idp }, use) => {
    const disabled = new Set<TestUser>();
    await use({
      async disable(user) {
        disabled.add(user);
        await idp.admin.setUserEnabled(user, false);
      },
    });
    for (const user of disabled) await idp.admin.setUserEnabled(user, true);
  },
  ssoSession: async ({ page }, use) => {
    await use(new SSOSession(page));
  },

  attemptSignInWithSSO: async ({ loginPage, idpLoginPage }, use) => {
    await use(async (user) => {
      await loginPage.open();
      await loginPage.startSingleSignOn();
      await idpLoginPage.signIn(user);
    });
  },
  signInWithSSO: async ({ attemptSignInWithSSO, app }, use) => {
    await use(async (user) => {
      await attemptSignInWithSSO(user);
      await expect(app.accountMenu).toContainText(user.email);
    });
  },
});

export { expect };
