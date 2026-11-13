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

import type { Page } from '@playwright/test';

/**
 * The tab's single sign-on session, reached through the WebUI's scripts.
 * Sessions last at least 15 minutes, so tests move the end closer instead
 * of waiting: the WebUI renews five minutes before the end, or warns when
 * it cannot renew.
 */
export class SSOSession {
  constructor(private readonly page: Page) {}

  /** The temporary access key the tab signs requests with. */
  async accessKey(): Promise<string | undefined> {
    return this.page.evaluate(() => api.credentials?.accessKey);
  }

  /**
   * Makes the credentials expire `ms` from now (negative: ago), and lets
   * the WebUI react as if the time had come.
   */
  async expireIn(ms: number): Promise<void> {
    await this.page.evaluate((ms) => {
      if (!api.credentials) throw new Error('the tab has no credentials');
      api.credentials.expiration = Date.now() + ms;
      sso._schedule();
    }, ms);
  }

  /** Drops the refresh token, as if the provider had issued none. */
  async forgetRefreshToken(): Promise<void> {
    await this.page.evaluate(() => {
      const session = sso.session();
      if (!session) throw new Error('the tab has no single sign-on session');
      sso._saveSession({ ...session, refreshToken: null });
    });
  }
}
