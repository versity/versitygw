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

/**
 * What every signed-in WebUI page has: the sidebar with the account menu,
 * toast notifications, and the single sign-on session banner.
 */
export class AppShell {
  /** Who is signed in; for single sign-on also the role and session end. */
  readonly accountMenu: Locator;
  readonly signOutButton: Locator;
  readonly toasts: Locator;
  /** Shown when a single sign-on session is about to end for good. */
  readonly sessionBanner: Locator;
  readonly signInAgainButton: Locator;
  private readonly confirmButton: Locator;

  constructor(private readonly page: Page) {
    this.accountMenu = page.locator('#user-info');
    this.signOutButton = page.getByRole('button', { name: 'Sign Out' });
    this.toasts = page.locator('#toast-container');
    this.sessionBanner = page.locator('#sso-session-banner');
    this.signInAgainButton = page.locator('#sso-session-banner-btn');
    this.confirmButton = page.locator('#confirm-ok');
  }

  async signOut(): Promise<void> {
    await this.signOutButton.click();
    // Some pages ask first; the dialog opens during the click.
    if (await this.confirmButton.isVisible()) await this.confirmButton.click();
  }

  /**
   * Identifies the document in the tab: it changes when the page reloads or
   * navigates, and only then.
   */
  async documentId(): Promise<number> {
    return this.page.evaluate(() => performance.timeOrigin);
  }
}
