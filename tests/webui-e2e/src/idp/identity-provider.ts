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

// What the tests need from an OpenID Connect identity provider. Each
// provider the WebUI is tested against implements this once, so that every
// single sign-on test runs against all of them unchanged.

import type { Locator, Page } from '@playwright/test';
import type { TestUser } from '../data/users';

/** The WebUI's public client at every provider; also the token audience. */
export const webuiClientId = 'versitygw-webui';

/** The ID token claim listing the role ARNs the user may assume. */
export const roleClaim = 'vgw_roles';

/** The ID token claim listing the user's group names. */
export const groupsClaim = 'groups';

export interface IdentityProvider {
  /** Lower-case name, used in project names: "keycloak". */
  readonly name: string;
  /** The issuer, exactly as the provider's discovery document states it. */
  readonly issuer: string;
  /** The scopes the WebUI requests, when its default ones are not enough. */
  readonly scopes?: string;
  /** The text of the WebUI's sign-in button for this provider. */
  readonly signInLabel: string;
  /** The provider's own sign-in page, in the given browser tab. */
  loginPage(page: Page): IdpLoginPage;
  /** Changes test users' accounts at the provider. */
  readonly admin: IdpAdmin;
}

export interface IdpLoginPage {
  /** The first field of the provider's sign-in form. */
  readonly usernameField: Locator;
  /** Fills in and submits the provider's sign-in form. */
  signIn(user: TestUser): Promise<void>;
}

export interface IdpAdmin {
  setUserEnabled(user: TestUser, enabled: boolean): Promise<void>;
}

export function discoveryUrl(idp: IdentityProvider): string {
  return `${idp.issuer.replace(/\/+$/, '')}/.well-known/openid-configuration`;
}
