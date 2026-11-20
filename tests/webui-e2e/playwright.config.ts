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

import { defineConfig, devices, type Project } from '@playwright/test';
import type { WebUIOptions } from './src/fixtures/webui';
import { gatewayNames, gateways } from './src/topology';

const ci = !!process.env.CI;

// tests/sso runs once per identity provider, through the gateway that
// signs in with it: projects sso-keycloak and sso-authentik.
const ssoProjects: Project<WebUIOptions>[] = gatewayNames.flatMap((name) => {
  const idp = gateways[name].sso;
  return idp ? [{ name: `sso-${idp.name}`, testDir: './tests/sso', use: { gatewayName: name } }] : [];
});

export default defineConfig<WebUIOptions>({
  globalSetup: './src/environment/global-setup.ts',
  projects: [...ssoProjects],

  fullyParallel: true,
  forbidOnly: ci,
  retries: ci ? 1 : 0,
  timeout: 60_000,
  expect: { timeout: 15_000 },
  reporter: ci
    ? [['github'], ['list'], ['html', { open: 'never' }]]
    : [['list'], ['html', { open: 'never' }]],

  use: {
    ...devices['Desktop Chrome'],
    actionTimeout: 15_000,
    navigationTimeout: 30_000,
    trace: 'retain-on-failure',
    screenshot: 'only-on-failure',
  },
});
