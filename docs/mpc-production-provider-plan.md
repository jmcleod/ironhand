# MPC Production Provider Plan

IronHand's current `experimental-p256-schnorr-v1` provider remains a development provider. It is useful for exercising vault membership, signer operations, policy enforcement, approvals, recovery import attestations, and UI flows, but it is not a production threshold-signing stack.

## Target Provider Boundary

The production provider is reserved as `frost-secp256k1-v1` and is visible through provider discovery, but it must report no usable keygen/signing capabilities until the implementation, vectors, crash-safety checks, and external review are complete. It must not replace or silently upgrade the experimental provider. Keys should always retain their original provider metadata.

The current implementation candidate and integration shape are documented in [ADR 0001: FROST secp256k1 Provider Candidate](adr/0001-frost-secp256k1-provider.md).

Provider metadata should be treated as the compatibility contract:

- `production_ready`: true only after external review and operational sign-off.
- `production_blockers`: a non-empty list for any provider that is visible but not production ready.
- `supports_keygen`: provider can run distributed key generation through registered signers.
- `supports_signing`: provider can produce signatures accepted by the target chain/runtime.
- `supports_reshare`: provider can replace membership without a full new key ceremony.
- `supports_recovery_import_attestations`: provider can verify signer-signed import attestations for recovery workflows.
- `deterministic_transcript_validation`: provider can canonicalize and verify signing transcripts before session completion.
- `chain_compatibility`: explicit target runtimes, for example `evm-secp256k1` or `bitcoin-secp256k1`.

## Acceptance Criteria For Production Readiness

1. Use a vetted FROST/secp256k1 implementation or a reviewed equivalent threshold-signing library.
2. Bind DKG, nonce commitments, signature shares, and final signatures to a canonical transcript with domain separation.
3. Verify signer identity, participant membership, threshold, key ID, vault ID, and DKG/session ID at every protocol step.
4. Persist signer state durably with crash-safe transitions for started, finalized, committed, aborted, and signing states.
5. Prevent nonce reuse across crashes and rejected signing attempts.
6. Support audited key rotation and, preferably, resharing semantics for membership changes.
7. Provide deterministic chain-specific signature serialization and verification tests against known vectors.
   - `evm-secp256k1`: 32-byte transaction hash input, deterministic recoverable signature serialization, and cross-checks against an independent secp256k1 verifier.
   - `bitcoin-secp256k1`: canonical sighash input, low-S normalization where required, and cross-checks against known script/witness validation vectors.
8. Pass adversarial integration, race, replay, crash/restart, and recovery-import tests in CI.
9. Receive independent cryptographic review before `production_ready` can be set to true.

## Migration Shape

- Keep experimental and production keys side-by-side; never reinterpret an existing key as a different provider.
- Add `frost-secp256k1-v1` behind a feature flag until reviewed.
- Keep `--mpc-production-mode` fail-closed: non-production providers cannot create keys or signing sessions.
- Add provider-specific WebUI warnings and chain compatibility labels before exposing production provider creation.
