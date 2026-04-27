#!/usr/bin/env bash
set -euo pipefail

# Runs the reproducible MPC demo harness. The Go test starts three HTTP signer
# services with durable sealed state, orchestrates DKG, approves locally, signs,
# and prints the resulting key/session metadata in verbose mode.
go test ./api -run '^TestMPCDemoHarness$' -count=1 -v
