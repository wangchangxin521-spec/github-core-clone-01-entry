// Forgelet entrypoint: bind an ephemeral port, register it with the trial
// environment, then poll until the environment says the trial is over.
//
// The environment's origin comes from MAKEFUN_ENV_URL. Without it there is
// nothing to register with, so the process exits 1 right away. The HTTP
// server itself lives in app.ts; this file only owns the lifecycle:
//
//   1. listen(0) so the kernel picks a free port (never 8080: the env owns it)
//   2. POST {port} to $MAKEFUN_ENV_URL/register (409 means a first register
//      already won; that is fine, we keep waiting like any other process)
//   3. GET $MAKEFUN_ENV_URL/done on a short poll until it says {"done": true}
//   4. close the server and exit 0
//
// A failed register or poll is retried with exponential backoff, capped, so
// a slow-starting environment does not kill the entry. Nothing here reads a
// wall clock into a request and nothing here is random: the only numbers are
// the bound port and the retry delays.

import { createApp } from './app.ts';

const envUrl = (process.env.MAKEFUN_ENV_URL ?? '').replace(/\/+$/, '');
if (envUrl === '') {
  process.stderr.write('[forgelet] MAKEFUN_ENV_URL is not set\n');
  process.exit(1);
}

const REQUEST_TIMEOUT_MS = 30_000;
const FIRST_RETRY_MS = 250;
const MAX_RETRY_MS = 2_000;

function sleep(ms: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

function backoff(attempt: number): number {
  const doubled = FIRST_RETRY_MS * 2 ** Math.min(attempt, 8);
  return Math.min(MAX_RETRY_MS, doubled);
}

async function registerPort(port: number): Promise<void> {
  for (let attempt = 0; ; attempt += 1) {
    try {
      const res = await fetch(`${envUrl}/register`, {
        method: 'POST',
        headers: { 'content-type': 'application/json' },
        body: JSON.stringify({ port }),
        signal: AbortSignal.timeout(REQUEST_TIMEOUT_MS),
      });
      if (res.status === 200 || res.status === 409) return;
      if (res.status === 400 || res.status === 405) {
        throw new Error(`register failed with HTTP ${res.status}`);
      }
    } catch (err) {
      if (err instanceof Error && err.message.startsWith('register failed')) throw err;
    }
    await sleep(backoff(attempt));
  }
}

async function waitUntilDone(): Promise<void> {
  for (let attempt = 0; ; attempt += 1) {
    try {
      const res = await fetch(`${envUrl}/done`, {
        signal: AbortSignal.timeout(REQUEST_TIMEOUT_MS),
      });
      if (res.ok) {
        const body = (await res.json()) as { done?: unknown };
        if (body.done === true) return;
      }
    } catch {
      // Not answering yet: keep polling.
    }
    await sleep(backoff(attempt));
  }
}

async function run(): Promise<void> {
  const server = createApp();
  await new Promise<void>((resolve, reject) => {
    server.once('error', reject);
    server.listen(0, () => resolve());
  });
  const addr = server.address();
  if (addr === null || typeof addr === 'string') {
    throw new Error('server did not bind a TCP port');
  }
  process.stdout.write(`[forgelet] listening on ${addr.port}\n`);
  await registerPort(addr.port);
  process.stdout.write('[forgelet] registered, waiting for done\n');
  await waitUntilDone();
  server.close();
  process.stdout.write('[forgelet] done\n');
}

try {
  await run();
  process.exit(0);
} catch (err) {
  process.stderr.write(`[forgelet] ${err instanceof Error ? err.message : String(err)}\n`);
  process.exit(1);
}
