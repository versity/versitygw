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

// The versitygw processes the tests run against:
//
//   - one standalone IAM service, which holds the accounts, the roles and
//     the registered identity providers;
//   - S3 gateways backed by it, each serving a WebUI on a port of its own.
//
// Every Playwright project names the one gateway its tests run against. To
// test the WebUI in another setup, add a gateway here and a project for it.
//
// The identity providers redirect only to the WebUI addresses registered
// with them, so a gateway with single sign-on must keep its webuiUrl in step
// with the provider's files under docker/.

import { localUrl } from './config';
import type { IdentityProvider } from './idp/identity-provider';
import { authentik } from './idp/authentik';
import { keycloak } from './idp/keycloak';

export interface IamService {
  /** The public IAM and STS API, which the WebUI calls. */
  readonly url: string;
}

export interface Gateway {
  readonly name: string;
  /** The S3 API. */
  readonly s3Url: string;
  /** The WebUI's login page. */
  readonly webuiUrl: string;
  /** Single sign-on through this provider on the login page, if any. */
  readonly sso?: IdentityProvider;
}

export const iamService: IamService = {
  url: localUrl(26100),
};

export const gateways = {
  keycloak: {
    name: 'keycloak',
    s3Url: localUrl(26110),
    webuiUrl: localUrl(26111, '/'),
    sso: keycloak,
  },
  authentik: {
    name: 'authentik',
    s3Url: localUrl(26120),
    webuiUrl: localUrl(26121, '/'),
    sso: authentik,
  },
} as const satisfies Record<string, Gateway>;

export type GatewayName = keyof typeof gateways;

export const gatewayNames = Object.keys(gateways) as GatewayName[];

export const allGateways: readonly Gateway[] = Object.values(gateways);

/** Every identity provider some gateway signs in with. */
export const allIdentityProviders: readonly IdentityProvider[] = [
  ...new Set(allGateways.flatMap((gateway) => (gateway.sso ? [gateway.sso] : []))),
];
