# IronHand Threat Model

## Scope

Current potential issues identified from the active implementation and deployment model.

## Current Known Potential Issues

### 1) Client IP trust boundary in proxy deployments (`Low`)

`extractClientIP` now correctly parses IPv4/IPv6 and supports `X-Forwarded-For`, `Forwarded`, and `X-Real-IP`, but these headers are only safe when injected by trusted reverse proxies/LBs.

- Impact: if clients can spoof forwarding headers, per-IP rate limiting can be bypassed or distorted.
- Evidence: `/Users/jmcleod/Development/Personal/ironhand/api/ratelimit.go`, `/Users/jmcleod/Development/Personal/ironhand/api/ratelimit_test.go`.
- Mitigation: enforce trusted proxy boundaries and strip/overwrite forwarding headers at the edge.

### 2) Audit retention defaults (`Low`)

Audit retention controls exist but default to disabled (`--audit-retention-days=0`, `--audit-max-entries=0`).

- Impact: deployments that keep defaults may accumulate unbounded audit history, creating governance/compliance and storage-management risk.
- Evidence: `/Users/jmcleod/Development/Personal/ironhand/cmd/ironhand/cmd/server.go`, `/Users/jmcleod/Development/Personal/ironhand/api/audit_store.go`.
- Mitigation: set environment-appropriate retention policy in deployment baselines.

### 3) PKI backend portability (`Low`)

PKCS#11 is implemented for hardware-backed key custody, but cloud KMS backends (AWS/GCP/Azure) are not included in-tree.

- Impact: environments without PKCS#11 may run software key custody unless they implement custom keystore integration.
- Evidence: `/Users/jmcleod/Development/Personal/ironhand/pki/keystore.go`, `/Users/jmcleod/Development/Personal/ironhand/pki/keystore_pkcs11.go`.
- Mitigation: add cloud KMS keystore adapters or provide deployment guidance for external integration.

## Operational Recommendations

1. Configure trusted reverse-proxy policy for forwarded headers before enabling internet-facing traffic.
2. Set `--audit-retention-days` and/or `--audit-max-entries` explicitly in production.
3. Choose hardware-backed PKI key custody (PKCS#11 or custom KMS backend) for high-assurance CA deployments.
