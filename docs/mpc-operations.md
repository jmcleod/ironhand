# MPC Operations Guide

IronHand MPC is still experimental unless the selected provider reports `production_ready: true`. The current `experimental-p256-schnorr-v1` provider is intended for protocol, API, and UI hardening only.

## Deployment Shape

- Run the API with `--enable-experimental-mpc` for the experimental provider.
- Use `--mpc-production-mode` in environments where non-production MPC providers must be refused.
- Configure signer transport with `--mpc-shared-key` or `IRONHAND_MPC_SHARED_KEY`.
- Prefer mTLS between the API and signers using `--mpc-client-cert`, `--mpc-client-key`, and `--mpc-signer-ca`.
- Run each signer with `--state-file` and `--state-passphrase` or `IRONHAND_MPC_SIGNER_STATE_KEY`.
- Use `--allow-insecure-mpc-local-dev` only for loopback demos and tests.

## Signer Health

Signers expose:

- `GET /signer/health`: liveness plus member ID, party ID, durable-state flag, key count, DKG status counts, and approval request counts.
- `GET /signer/ready`: readiness with the same payload, returning `503` if signer identity is not usable.
- `GET /signer/approval-requests`: pending/local approval queue for the operator token flow.

## Vault MPC Metrics

The API exposes `GET /api/v1/vaults/<vault_id>/mpc/metrics`, returning counts for:

- MPC keys by lifecycle status.
- DKG attempts by status.
- Signing sessions by status.

These are intended for dashboards and alerting. They are vault-scoped and require normal vault authentication.

## Audit Events

MPC audit events include signer registration, DKG commit/abort, key creation, key rotation, key status changes, signing requests, approval requests, approvals, and signing completion.

## Backup And Restore

Signer state files contain sealed signer identity, DKG/key state, and local approval requests. Back up signer state files with the same care as encrypted vault storage:

- Back up each signer state file after DKG/key changes.
- Store signer state passphrases in a separate secret manager.
- Restore signer state to the same member ID and party ID.
- Do not clone one signer state file to another party.

## Runbook

1. Check signer readiness before DKG: `curl http://signer:8081/signer/ready`.
2. Create a key and watch `GET /mpc/dkg` or `GET /mpc/metrics` for DKG status.
3. If DKG fails, inspect `last_error` on the DKG attempt and abort stale attempts.
4. For signing, request approvals from selected parties, approve locally on each signer, then complete the session.
5. After member revocation, rotate affected keys using replacement-key rotation; keys marked `reshare_required` should not be treated as clean production keys.
