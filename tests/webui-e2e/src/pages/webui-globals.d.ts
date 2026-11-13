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

// The WebUI's own scripts declare these at the top level of every page, as
// const bindings rather than properties of window. Only the parts that
// page.evaluate callbacks use are typed here.

interface WebUICredentials {
  accessKey: string;
  sessionToken?: string;
  /** When the credentials expire, in milliseconds since the epoch. */
  expiration?: number;
}

interface WebUISSOSessionState {
  roleArn: string;
  refreshToken: string | null;
}

/** The WebUI's client for the S3 and IAM APIs. */
declare const api: {
  credentials: WebUICredentials | null;
};

/** The WebUI's single sign-on session manager. */
declare const sso: {
  session(): WebUISSOSessionState | null;
  _saveSession(session: WebUISSOSessionState): void;
  /** Plans the next renewal or warning from the credentials' expiration. */
  _schedule(): void;
};
