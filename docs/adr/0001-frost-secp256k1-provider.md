# ADR 0001: FROST secp256k1 Provider Candidate

Status: Proposed
Date: 2026-05-01

## Context

IronHand reserves `frost-secp256k1-v1` as the production MPC provider identifier, while `experimental-p256-schnorr-v1` remains a development-only provider. The next MPC milestone needs a concrete implementation target for secp256k1 threshold signing without weakening the current fail-closed production boundary.

The provider must support EVM and Bitcoin secp256k1 workflows, deterministic transcript validation, durable signer state, nonce-reuse prevention, and chain-specific signature serialization tests before it can report production readiness.

## Decision

Use `github.com/bytemare/frost` as the first integration candidate for `frost-secp256k1-v1`, behind the existing production-readiness gates and a disabled-by-default feature flag.

This is a candidate selection, not a production approval. The provider must continue to report `production_ready: false`, `supports_keygen: false`, and `supports_signing: false` until the acceptance gates in `docs/mpc-production-provider-plan.md` pass and the external review gate is complete.

## Rationale

- It is Go-native and aligns with IronHand's current backend runtime.
- It implements RFC 9591 FROST and supports the secp256k1/SHA-256 ciphersuite required for the reserved provider.
- Its API can be isolated behind IronHand's provider boundary instead of leaking protocol-specific types into vault, policy, or WebUI layers.
- Coinbase Kryptology includes threshold cryptography work, but the repository is archived and explicitly unsupported, so it should not be the primary dependency.
- C or experimental libsecp256k1-based forks can remain useful for interop checks, but they should not become the application dependency unless review findings require that direction.

## Integration Shape

1. Add an internal adapter package for `frost-secp256k1-v1`.
2. Keep public MPC provider metadata stable and expose only capability changes through provider discovery.
3. Persist the selected ciphersuite, context string, participant roster, threshold, key ID, vault ID, DKG ID, and signing session ID in canonical transcripts.
4. Decode and validate every protocol message at the adapter boundary before it reaches signer state transitions.
5. Keep DKG, signing, resharing, and recovery-import capabilities disabled until their individual readiness gates pass.
6. Add chain adapters for EVM and Bitcoin serialization instead of embedding chain-specific rules in the FROST provider core.

## Acceptance Gates

- RFC 9591 secp256k1/SHA-256 test vectors pass in CI.
- Generated signatures verify against at least one independent secp256k1 verifier for each target chain.
- DKG, nonce commitment, signature share, aggregation, abort, and retry flows are covered with crash/restart tests.
- Nonce state is single-use across rejected sessions, signer restarts, and coordinator retries.
- Transcripts reject participant, threshold, key, vault, DKG, chain, and session mismatches.
- Recovery import remains gated on signer-signed attestations and never bypasses provider compatibility checks.
- Independent cryptographic review is complete before `production_ready` can become true.

## Consequences

- IronHand can start implementation against a concrete library while preserving the existing production safety boundary.
- The provider adapter becomes the enforcement point for protocol-specific validation, serialization, and compatibility.
- The project still needs review evidence, known-answer vectors, interop tests, and operational runbooks before production use.

## Follow-Up Work

1. Spike the dependency in the adapter package and compile a minimal trusted-dealer or DKG flow without enabling provider capabilities.
2. Add RFC 9591 vector fixtures and independent verifier checks.
3. Implement durable DKG and signing transcript persistence.
4. Add crash/restart tests around nonce allocation and signing session aborts.
5. Wire the WebUI to surface provider capability details without offering disabled actions.
