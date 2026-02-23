import { readFileSync, rmSync, existsSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

const STATE_FILE = join(tmpdir(), 'ironhand-e2e-state.json');

export default async function globalTeardown(): Promise<void> {
  if (!existsSync(STATE_FILE)) {
    console.log('[e2e] No state file found — nothing to tear down');
    return;
  }

  const state = JSON.parse(readFileSync(STATE_FILE, 'utf-8')) as {
    pid: number;
    tmpDir: string;
  };

  // Send SIGTERM to the server process.
  if (state.pid) {
    console.log(`[e2e] Stopping server (PID ${state.pid})...`);
    try {
      process.kill(state.pid, 'SIGTERM');
      // Wait briefly for graceful shutdown.
      await new Promise((resolve) => setTimeout(resolve, 2_000));
    } catch {
      // Process may have already exited — that's fine.
    }
  }

  // Remove temp directory.
  if (state.tmpDir && existsSync(state.tmpDir)) {
    console.log(`[e2e] Cleaning up temp directory: ${state.tmpDir}`);
    rmSync(state.tmpDir, { recursive: true, force: true });
  }

  // Clean up state file.
  rmSync(STATE_FILE, { force: true });

  console.log('[e2e] Teardown complete');
}
