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
- Signer readiness/status across MPC key participants.
- Derived action counts for keys requiring rotation/reshare/repair, non-production provider keys, and missing pending approvals.

These are intended for dashboards and alerting. They are vault-scoped and require normal vault authentication.

## Key Generation And Rotation

Coordinator-run DKG stores a vault DKG attempt, starts/finalizes selected signers, stores the vault key record, and then requires every selected signer to durably commit the key. If any signer commit fails, the attempt is marked failed and the key is disabled instead of being treated as active.

Replacement-key rotation follows the same rule and only archives the old key after all selected signers commit the replacement. This prevents a vault from moving to a replacement key that signer processes cannot actually use.

Manual key imports are deliberately narrow. Supplied fragments must be keyed by member ID, bound to the requested key ID and party ID, use the supported encrypted-fragment envelope, and expose a public share commitment that matches the submitted DKG commitments. The vault still cannot decrypt signer fragments, so it requires signer attestations and envelope-hash binding for recovery imports. A future production provider should add provider-specific import proofs or disable manual import entirely.

## Policy And Completion Validation

`max_value` is enforced during signing-session creation. Both `policy.max_value` and transaction metadata `value` are non-negative decimal integer strings in the target chain's smallest unit. If `max_value` is configured and the transaction value is missing, malformed, or above the limit, session creation is denied.

Signing sessions with a non-empty `chain` are refused unless the selected provider advertises that chain in `chain_compatibility`. The experimental P-256 provider is limited to development compatibility labels and cannot create `evm-secp256k1` or `bitcoin-secp256k1` sessions.

Manual signing completion must submit commitments that exactly match `signature.commitments`; those commitments must be a threshold-sized subset of the selected session participants and each signature share must correspond to a commitment. The session stores the canonical commitments from the verified signature transcript.

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

## Recovery Import Procedure

Recovery import is available from the WebUI MPC Recovery tab and `POST /api/v1/vaults/<vault_id>/mpc/keys` with `import_mode: "recovery"` only when the API server was started with `--enable-mpc-recovery-import`.

The request must include:

- `dkg_session_id` from the ceremony that produced the artifacts.
- `threshold` and the intended member set.
- `commitments` from every selected DKG participant.
- `fragments` keyed by member ID.
- Per-fragment signer attestations covering vault ID, key ID, party ID, DKG session ID, commitments hash, public share commitment, approval public key, and encrypted fragment envelope hash.

The vault rejects recovery artifacts if the public share commitment does not match the DKG commitments, if the attested envelope hash does not match the encrypted fragment payload, or if the signer attestation does not verify against the registered member approval key.

## Threat Model

The MPC integration threat model and invariant-to-test map are maintained in `docs/security/mpc-threat-model.md`.
