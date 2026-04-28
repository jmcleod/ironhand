# MPC Threat Model

IronHand treats each vault as the MPC group. The API coordinates ceremonies, the vault stores encrypted metadata and signer fragments, and signer processes hold durable sealed signer identity plus local MPC state. The current provider, `experimental-p256-schnorr-v1`, is not production cryptography; this model exists to keep the integration safe while the provider remains experimental.

## Security Boundaries

- Browser/WebUI: untrusted operator interface. It can request API actions but must not be trusted for policy or transcript decisions.
- API/coordinator: trusted to enforce vault authorization, DKG orchestration, session policy, transcript validation, and audit logging.
- Vault storage: untrusted durable storage. Records are sealed by vault keys; storage can replay or omit records unless version/CAS and record validation detect it.
- MPC signer: trusted only for its own party. A signer must not approve or sign outside keys and sessions bound to its member identity.
- Internal signer transport: authenticated coordinator-to-signer channel. HMAC-signed requests and mTLS are expected outside loopback development.
- Operator token: local signer authorization for approval queue actions. It is not a vault credential and must not authorize arbitrary signing without a queued request.
- Recovery artifacts: untrusted until validated against DKG commitments, signer identities, DKG session ID, public share commitments, and encrypted fragment envelope hashes.

## Primary Adversaries

- Compromised browser session attempting to bypass vault policy or submit poisoned recovery artifacts.
- Compromised or exposed internal caller attempting to mint signer approvals or replay signer requests.
- Malicious storage layer replaying stale DKG, key, fragment, or signing-session records.
- Dishonest vault member submitting malformed DKG commitments, duplicate participants, or transcript metadata.
- Crashed signer or coordinator leaving partial DKG/key state behind.
- Revoked member retaining old local state and attempting to use stale key material.

## Required Invariants

- A signer approval is bound to one vault ID, key ID, session ID, threshold, participant set, message hash, transaction context, and expiry.
- A signer emits an approval only after a stored local approval request is approved with the operator token.
- A signer nonce is single-use per signing session and cannot be overwritten with a different transcript.
- Signing completion accepts any threshold-sized valid subset, but only before session expiry and only with canonical commitments from the verified signature transcript.
- DKG either commits to every selected signer or leaves the created key disabled/failed and keeps the previous active key usable during rotation.
- Recovery/manual imports require `import_mode: recovery`, a `dkg_session_id`, signer attestations, matching public share commitments, and an attestation hash over the encrypted fragment envelope.
- Vault policy fails closed when `max_value` cannot be parsed or when transaction value is missing under a configured ceiling.
- Experimental providers cannot be used when production-mode gating is enabled.

## Test Map

- `internal/mpcsigner/service_test.go`: signer approval binding, local approval queue, nonce idempotence, wrong-party signing rejection, health/status shape.
- `internal/mpc/mpc_test.go`: DKG/signature math, provider production metadata, participant normalization, fragment envelope attestation binding, fragment validation rejection cases.
- `vault/mpc_test.go`: vault key creation, fragment attestation validation, signing-session policy, threshold completion, expiry, transcript canonicalization, revocation reshare status.
- `api/mpc_demo_test.go`: coordinator DKG orchestration, durable signer restart, DKG failure recording, signer commit failure handling, manual import API gating, production-mode gating, replacement rotation behavior.
- `api/openapi_drift_test.go`: API route documentation parity.

## Production-Readiness Gates

- Replace the experimental P-256 Schnorr-style provider with an externally reviewed threshold-signing provider for the target chain.
- Add known-answer vectors and adversarial transcript tests for the production provider.
- Require authenticated signer transport in non-development deployments.
- Exercise crash/restart tests across DKG start, finalize, commit, approval, nonce commitment, and signing-share generation.
- Require independent cryptographic review before any provider reports `production_ready: true`.
