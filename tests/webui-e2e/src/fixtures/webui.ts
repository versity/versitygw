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

// The fixtures every WebUI test can use. Tests import test and expect from
// here, or from a module that extends this one.

import { test as base } from '@playwright/test';
import { AppShell } from '../pages/app-shell';
import { ExplorerPage } from '../pages/explorer-page';
import { LoginPage } from '../pages/login-page';
import { type Gateway, type GatewayName, gateways } from '../topology';

export interface WebUIOptions {
  /** The gateway whose WebUI the project's tests use; set per project. */
  gatewayName: GatewayName | undefined;
}

interface WebUIWorkerFixtures {
  gateway: Gateway;
}

export interface WebUIFixtures {
  loginPage: LoginPage;
  app: AppShell;
  explorer: ExplorerPage;
  /** A key prefix no other test uses, for the objects this test creates. */
  keyPrefix: string;
}

export const test = base.extend<WebUIFixtures, WebUIOptions & WebUIWorkerFixtures>({
  gatewayName: [undefined, { option: true, scope: 'worker' }],
  gateway: [
    async ({ gatewayName }, use) => {
      if (!gatewayName) throw new Error('the Playwright project sets no gatewayName');
      await use(gateways[gatewayName]);
    },
    { scope: 'worker' },
  ],

  loginPage: async ({ page, gateway }, use) => {
    await use(new LoginPage(page, gateway.webuiUrl));
  },
  app: async ({ page }, use) => {
    await use(new AppShell(page));
  },
  explorer: async ({ page, gateway }, use) => {
    await use(new ExplorerPage(page, gateway.webuiUrl));
  },
  keyPrefix: async ({}, use, testInfo) => {
    await use(`e2e-${testInfo.testId}/`);
  },
});

export { expect } from '@playwright/test';
