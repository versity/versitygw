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

// Keycloak, as docker/compose.yml runs it with the realm in
// docker/keycloak.

import type { Locator, Page } from '@playwright/test';
import { localUrl } from '../config';
import type { TestUser } from '../data/users';
import type { IdentityProvider, IdpAdmin, IdpLoginPage } from './identity-provider';
import { requestJson } from './http';

const baseUrl = localUrl(26180);
const realm = 'versitygw';
const adminCredentials = { username: 'admin', password: 'admin' };

class KeycloakLoginPage implements IdpLoginPage {
  readonly usernameField: Locator;
  private readonly passwordField: Locator;
  private readonly submitButton: Locator;

  constructor(page: Page) {
    this.usernameField = page.getByLabel('Username or email');
    this.passwordField = page.getByLabel('Password', { exact: true });
    this.submitButton = page.getByRole('button', { name: 'Sign In' });
  }

  async signIn(user: TestUser): Promise<void> {
    await this.usernameField.fill(user.username);
    await this.passwordField.fill(user.password);
    await this.submitButton.click();
  }
}

/** The admin REST API, signed in as the bootstrap admin of the master realm. */
class KeycloakAdmin implements IdpAdmin {
  async setUserEnabled(user: TestUser, enabled: boolean): Promise<void> {
    const token = await this.accessToken();
    const id = await this.userId(user, token);
    await requestJson(`${baseUrl}/admin/realms/${realm}/users/${id}`, {
      method: 'PUT',
      bearerToken: token,
      json: { enabled },
    });
  }

  private async userId(user: TestUser, token: string): Promise<string> {
    const query = new URLSearchParams({ username: user.username, exact: 'true' });
    const found = await requestJson<{ id: string }[]>(`${baseUrl}/admin/realms/${realm}/users?${query}`, {
      bearerToken: token,
    });
    if (found.length !== 1) throw new Error(`Keycloak has no user ${user.username} in realm ${realm}`);
    return found[0].id;
  }

  // Admin tokens last a minute, so every call gets a new one.
  private async accessToken(): Promise<string> {
    const tokens = await requestJson<{ access_token: string }>(`${baseUrl}/realms/master/protocol/openid-connect/token`, {
      form: { grant_type: 'password', client_id: 'admin-cli', ...adminCredentials },
    });
    return tokens.access_token;
  }
}

export const keycloak: IdentityProvider = {
  name: 'keycloak',
  issuer: `${baseUrl}/realms/${realm}`,
  signInLabel: 'Sign in with Keycloak',
  loginPage: (page) => new KeycloakLoginPage(page),
  admin: new KeycloakAdmin(),
};
