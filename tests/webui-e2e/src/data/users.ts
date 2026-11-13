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

// The identity providers' test users. Every provider has all of them, with
// the same groups: the Keycloak realm and the authentik blueprint under
// docker/ create them. A group's role ARNs become the user's role claim.

export interface TestUser {
  readonly username: string;
  readonly password: string;
  readonly email: string;
}

export const users = {
  /** In s3-admins: one role, full S3 access. */
  alice: testUser('alice'),
  /** In s3-readers: one role, list and download only. */
  bob: testUser('bob'),
  /** In s3-admins and s3-readers: two roles to choose from. */
  carol: testUser('carol'),
  /** In no group, so the role claim is empty. */
  dave: testUser('dave'),
  /**
   * In contractors, a group whose role claim names s3-admins. That role
   * trusts only members of s3-admins, so the gateway refuses her.
   */
  mallory: testUser('mallory'),
  /**
   * In s3-readers. Reserved for the tests that change the account, such as
   * disabling it, so that no other test runs into the change.
   */
  frank: testUser('frank'),
} as const satisfies Record<string, TestUser>;

function testUser(username: string): TestUser {
  return { username, password: username, email: `${username}@example.com` };
}
