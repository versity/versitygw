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

import type { Locator, Page } from '@playwright/test';
import type { TestRole } from '../data/roles';

/**
 * The WebUI login page (index.html): the single sign-on button, the role
 * picker it can lead to, and the access-key form.
 */
export class LoginPage {
  readonly singleSignOnButton: Locator;
  /** The "or use access keys" divider between the two ways in. */
  readonly accessKeyDivider: Locator;
  readonly accessKeyField: Locator;
  readonly secretKeyField: Locator;
  readonly accessKeySignInButton: Locator;
  /** The message of the error alert above the form. */
  readonly errorMessage: Locator;
  /** One button per role, when the identity provider offered several. */
  readonly roleChoices: Locator;

  constructor(
    private readonly page: Page,
    private readonly url: string,
  ) {
    this.singleSignOnButton = page.locator('#sso-btn');
    this.accessKeyDivider = page.getByText('or use access keys');
    this.accessKeyField = page.locator('#access-key');
    this.secretKeyField = page.locator('#secret-key');
    this.accessKeySignInButton = page.locator('#submit-btn');
    this.errorMessage = page.locator('#error-message');
    this.roleChoices = page.locator('#sso-role-list button');
  }

  async open(): Promise<void> {
    await this.page.goto(this.url);
  }

  /** Leaves for the identity provider. */
  async startSingleSignOn(): Promise<void> {
    await this.singleSignOnButton.click();
  }

  /**
   * Resolves when the identity provider next sends the tab back here with
   * an authorization code. Call it before whatever leads there.
   */
  async waitForProviderCallback(): Promise<void> {
    await this.page.waitForURL((url) => url.href.startsWith(this.url) && url.searchParams.has('code'));
  }

  async signInWithAccessKeys(accessKey: string, secretKey: string): Promise<void> {
    await this.accessKeyField.fill(accessKey);
    await this.secretKeyField.fill(secretKey);
    await this.accessKeySignInButton.click();
  }

  /** The role picker's button for a role, labelled with its name. */
  roleChoice(role: TestRole): Locator {
    return this.roleChoices.filter({ has: this.page.getByText(role.name, { exact: true }) });
  }

  async chooseRole(role: TestRole): Promise<void> {
    await this.roleChoice(role).click();
  }
}
