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

import { type ChildProcess, execFile, spawn } from 'node:child_process';
import { closeSync, openSync, readFileSync } from 'node:fs';
import { promisify } from 'node:util';
import { respondsOk, waitUntil } from './wait';

const readyTimeoutMs = 30_000;
const stopTimeoutMs = 5_000;

export interface ServiceSpec {
  /** Names the process in errors. */
  name: string;
  command: string;
  args: readonly string[];
  /** Receives the process's output. */
  logFile: string;
  /** The process is ready once a GET of each of these succeeds. */
  readyUrls: readonly string[];
}

/** Long-running processes that are started one by one and stopped together. */
export class ServiceGroup {
  private readonly services: ServiceProcess[] = [];

  /**
   * Starts a process and waits until it is ready. The group stops it with
   * the others even when it never gets ready.
   */
  async start(spec: ServiceSpec): Promise<void> {
    const service = new ServiceProcess(spec);
    this.services.push(service);
    for (const url of spec.readyUrls) await service.waitUntilServing(url);
  }

  async stopAll(): Promise<void> {
    await Promise.all(this.services.map((service) => service.stop()));
  }
}

/** Runs a command to completion; throws with its output when it fails. */
export async function runCommand(command: string, args: readonly string[], cwd: string): Promise<void> {
  try {
    await promisify(execFile)(command, [...args], { cwd });
  } catch (error) {
    const { stdout = '', stderr = '' } = error as { stdout?: string; stderr?: string };
    throw new Error(`${command} ${args.join(' ')} failed:\n${stdout}${stderr}`, { cause: error });
  }
}

interface Exit {
  code: number | null;
  signal: NodeJS.Signals | null;
}

class ServiceProcess {
  private readonly child: ChildProcess;
  private exit: Exit | null = null;
  private readonly exited: Promise<Exit>;

  constructor(private readonly spec: ServiceSpec) {
    const log = openSync(spec.logFile, 'w');
    try {
      this.child = spawn(spec.command, spec.args, { stdio: ['ignore', log, log] });
    } finally {
      // The child has its own copy of the descriptor.
      closeSync(log);
    }
    this.exited = new Promise((resolve) => {
      this.child.once('exit', (code, signal) => {
        this.exit = { code, signal };
        resolve(this.exit);
      });
    });
  }

  /** Fails at once, with the end of the log, when the process exits first. */
  async waitUntilServing(url: string): Promise<void> {
    const { name, logFile } = this.spec;
    await waitUntil(
      async () => {
        if (this.exit) {
          throw new Error(`${name} exited (${describeExit(this.exit)}) before serving ${url}:\n${this.logTail()}`);
        }
        return respondsOk(url);
      },
      { what: `${name} to serve ${url} (log: ${logFile})`, timeoutMs: readyTimeoutMs },
    );
  }

  /** SIGTERM, then SIGKILL if the process lingers. */
  async stop(): Promise<void> {
    if (this.exit) return;
    this.child.kill('SIGTERM');
    const kill = setTimeout(() => this.child.kill('SIGKILL'), stopTimeoutMs);
    await this.exited;
    clearTimeout(kill);
  }

  private logTail(lines = 30): string {
    return readFileSync(this.spec.logFile, 'utf8').trimEnd().split('\n').slice(-lines).join('\n');
  }
}

function describeExit(exit: Exit): string {
  return exit.signal ? `signal ${exit.signal}` : `status ${exit.code}`;
}
