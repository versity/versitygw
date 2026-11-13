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

// authentik, as docker/compose.yml runs it with the blueprint in
// docker/authentik.

import type { Locator, Page } from '@playwright/test';
import { localUrl } from '../config';
import type { TestUser } from '../data/users';
import { type IdentityProvider, type IdpAdmin, type IdpLoginPage, roleClaim } from './identity-provider';
import { requestJson } from './http';

const baseUrl = localUrl(26190);
const applicationSlug = 'versitygw';
/** The API token the compose file bootstraps authentik with. */
const apiToken = 'webui-e2e-api-token';

/** The default authentication flow: the username first, then the password. */
class AuthentikLoginPage implements IdpLoginPage {
  readonly usernameField: Locator;
  private readonly passwordField: Locator;
  private readonly logInButton: Locator;
  private readonly continueButton: Locator;

  constructor(page: Page) {
    this.usernameField = page.getByLabel('Email or Username');
    this.passwordField = page.getByLabel('Password', { exact: true });
    this.logInButton = page.getByRole('button', { name: 'Log in' });
    this.continueButton = page.getByRole('button', { name: 'Continue' });
  }

  async signIn(user: TestUser): Promise<void> {
    await this.usernameField.fill(user.username);
    await this.logInButton.click();
    await this.passwordField.fill(user.password);
    await this.continueButton.click();
  }
}

/** The REST API, with the bootstrap API token. */
class AuthentikAdmin implements IdpAdmin {
  async setUserEnabled(user: TestUser, enabled: boolean): Promise<void> {
    const pk = await this.userPk(user);
    await requestJson(`${baseUrl}/api/v3/core/users/${pk}/`, {
      method: 'PATCH',
      bearerToken: apiToken,
      json: { is_active: enabled },
    });
  }

  private async userPk(user: TestUser): Promise<number> {
    const query = new URLSearchParams({ username: user.username });
    const found = await requestJson<{ results: { pk: number }[] }>(`${baseUrl}/api/v3/core/users/?${query}`, {
      bearerToken: apiToken,
    });
    if (found.results.length !== 1) throw new Error(`authentik has no user ${user.username}`);
    return found.results[0].pk;
  }
}

export const authentik: IdentityProvider = {
  name: 'authentik',
  issuer: `${baseUrl}/application/o/${applicationSlug}/`,
  // Refresh tokens come only with offline_access, and the role claim with
  // its own scope.
  scopes: `openid profile email offline_access ${roleClaim}`,
  signInLabel: 'Sign in with authentik',
  loginPage: (page) => new AuthentikLoginPage(page),
  admin: new AuthentikAdmin(),
};
