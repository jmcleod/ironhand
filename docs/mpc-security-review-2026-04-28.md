# MPC Focused Security Review - 2026-04-28

Scope: post-hardening review of the MPC coordinator, signer, vault policy, transcript validation, rotation, provider gating, and documentation state on `master` after commit `7d2bd35`.

## Reviewed Areas

- DKG lifecycle in `api/mpc_handlers.go`, including start, finalize, abort, commit, create-key, and replacement rotation paths.
- Signer request validation in `internal/mpcsigner/service.go`, including approval requests, local operator approval, nonce commits, signing shares, and signer health/readiness endpoints.
- Internal signer transport authentication and replay handling in `internal/mpcclient`.
- Vault MPC invariants in `vault/mpc.go`, including key creation, fragment validation, approval binding, policy evaluation, completion, expiry, and key lifecycle checks.
- Provider boundaries in `internal/mpc/provider.go`, especially production-mode metadata and experimental-provider capability limits.
- API contract, WebUI type surface, and operational docs for MPC behavior.

## Findings

No new high-priority implementation blocker was found in the already-hardened paths. The previous concrete issues were addressed: signer commit failure is now surfaced, `max_value` is enforced, completion transcripts are bound to verified signature data, and imported fragments are checked against DKG public commitments.

## Residual Risks To Address In This Workstream

- Manual MPC key import remains a recovery-sensitive path. It now validates public fragment consistency, but the vault still cannot decrypt signer fragments; normal API creation should prefer orchestrated DKG, with manual import gated behind an explicit recovery mode and signer attestations.
- The experimental P-256 Schnorr provider is still not a production-vetted threshold-signing implementation. Production mode correctly rejects it, but the provider interface should be prepared for a real FROST/secp256k1 or chain-specific provider.
- Adversarial regression coverage should be expanded so stale approvals, wrong signer parties, replayed internal calls, malformed policy values, failed create/rotate commits, and transcript mismatches stay fixed.
- Operator visibility should improve around signer readiness, DKG failure recovery, approval queues, policy rejection reasons, and key states requiring rotation or reshare.
- CI should continuously check OpenAPI/type consistency, production-mode provider rejection, and signer/coordinator race-sensitive packages.

## Remediation Order

1. Expand adversarial MPC tests.
2. Gate and attest manual key import.
3. Add production provider design/stub boundaries.
4. Improve WebUI operator flows for MPC failures and approvals.
5. Add CI/security automation for MPC regressions.
