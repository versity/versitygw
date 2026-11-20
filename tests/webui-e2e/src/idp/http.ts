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

// A minimal JSON client for the identity providers' admin APIs.

export interface JsonRequest {
  method?: string;
  bearerToken?: string;
  /** Sent as JSON. */
  json?: unknown;
  /** Sent as an HTML form. */
  form?: Record<string, string>;
}

/**
 * Sends a request and returns its JSON response, or undefined for an empty
 * one. Throws on any status other than 2xx.
 */
export async function requestJson<T>(url: string, request: JsonRequest = {}): Promise<T> {
  const headers: Record<string, string> = { Accept: 'application/json' };
  let body: string | undefined;
  if (request.bearerToken) headers.Authorization = `Bearer ${request.bearerToken}`;
  if (request.json !== undefined) {
    headers['Content-Type'] = 'application/json';
    body = JSON.stringify(request.json);
  } else if (request.form) {
    headers['Content-Type'] = 'application/x-www-form-urlencoded';
    body = new URLSearchParams(request.form).toString();
  }

  const method = request.method ?? (body === undefined ? 'GET' : 'POST');
  const response = await fetch(url, { method, headers, body });
  const text = await response.text();
  if (!response.ok) {
    throw new Error(`${method} ${url}: HTTP ${response.status} ${text}`);
  }
  return (text ? JSON.parse(text) : undefined) as T;
}
