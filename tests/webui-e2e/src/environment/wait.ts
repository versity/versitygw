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

import { setTimeout as sleep } from 'node:timers/promises';

export interface WaitOptions {
  /** What is being waited for, as the timeout error names it. */
  what: string;
  timeoutMs: number;
  intervalMs?: number;
}

/**
 * Calls check until it returns true. An error thrown by check ends the wait
 * at once.
 */
export async function waitUntil(check: () => Promise<boolean>, options: WaitOptions): Promise<void> {
  const { what, timeoutMs, intervalMs = 200 } = options;
  const deadline = Date.now() + timeoutMs;
  while (!(await check())) {
    if (Date.now() >= deadline) {
      throw new Error(`Timed out after ${timeoutMs / 1000}s waiting for ${what}`);
    }
    await sleep(intervalMs);
  }
}

/** Whether a GET of the URL answers with a 2xx status. */
export async function respondsOk(url: string): Promise<boolean> {
  try {
    const response = await fetch(url, { signal: AbortSignal.timeout(2_000) });
    await response.body?.cancel();
    return response.ok;
  } catch {
    return false;
  }
}
