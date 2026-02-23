import { execSync, spawn, type ChildProcess } from 'node:child_process';
import { mkdtempSync, writeFileSync, mkdirSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import https from 'node:https';

const PORT = 9443;
const HEALTH_URL = `https://localhost:${PORT}/health`;
const STATE_FILE = join(tmpdir(), 'ironhand-e2e-state.json');

/** Poll the /health endpoint until it responds or timeout is reached. */
function waitForHealth(timeoutMs: number): Promise<void> {
  const start = Date.now();
  return new Promise((resolve, reject) => {
    const poll = () => {
      if (Date.now() - start > timeoutMs) {
        reject(new Error(`Server did not become healthy within ${timeoutMs}ms`));
        return;
      }
      const req = https.get(
        HEALTH_URL,
        { rejectUnauthorized: false },
        (res) => {
          if (res.statusCode === 200) {
            resolve();
          } else {
            setTimeout(poll, 500);
          }
        },
      );
      req.on('error', () => setTimeout(poll, 500));
      req.end();
    };
    poll();
  });
}

export default async function globalSetup(): Promise<void> {
  const projectRoot = join(__dirname, '..');

  // Create a temp directory for this test run.
  const tmpDir = mkdtempSync(join(tmpdir(), 'ironhand-e2e-'));
  const dataDir = join(tmpDir, 'data');
  mkdirSync(dataDir, { recursive: true });
  const binaryPath = join(tmpDir, 'ironhand');

  console.log(`[e2e] Temp directory: ${tmpDir}`);
  console.log(`[e2e] Building Go binary...`);

  // Build the Go binary (web/dist must already exist — handled by Taskfile _web:dist dep).
  execSync(`go build -o ${binaryPath} ./cmd/ironhand`, {
    cwd: projectRoot,
    stdio: 'inherit',
    timeout: 120_000,
  });

  console.log(`[e2e] Starting server on port ${PORT}...`);

  // Spawn the server.
  const server: ChildProcess = spawn(
    binaryPath,
    [
      'server',
      '--port', String(PORT),
      '--storage', 'bbolt',
      '--data-dir', dataDir,
      '--kdf-profile', 'interactive',
      '--no-rate-limit',
    ],
    {
      cwd: projectRoot,
      stdio: 'pipe',
      detached: false,
    },
  );

  // Forward server output for debugging.
  server.stdout?.on('data', (data: Buffer) => {
    process.stdout.write(`[server] ${data.toString()}`);
  });
  server.stderr?.on('data', (data: Buffer) => {
    process.stderr.write(`[server:err] ${data.toString()}`);
  });

  server.on('error', (err) => {
    console.error(`[e2e] Server process error:`, err);
  });

  server.on('exit', (code, signal) => {
    console.log(`[e2e] Server exited (code=${code}, signal=${signal})`);
  });

  // Persist state for teardown.
  const state = {
    pid: server.pid,
    tmpDir,
  };
  writeFileSync(STATE_FILE, JSON.stringify(state));

  // Wait for the server to be ready.
  try {
    await waitForHealth(30_000);
    console.log(`[e2e] Server is healthy on port ${PORT}`);
  } catch (err) {
    // Kill the server if it failed to start.
    if (server.pid) {
      process.kill(server.pid, 'SIGTERM');
    }
    throw err;
  }
}
