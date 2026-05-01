# FROST secp256k1 Test Fixtures

`rfc9591-frost-secp256k1-sha256.json` is copied from `github.com/bytemare/frost` at module version `v0.0.0-20241019112700-8c6db5b04145`.

The fixture covers `FROST(secp256k1, SHA-256)` with RFC 9591-style signing inputs, nonce commitments, signature shares, and final signature output. IronHand keeps a local copy so adapter tests are stable and reviewable even if the upstream module layout changes.

Refresh procedure:

1. Update `github.com/bytemare/frost` in `go.mod`.
2. Copy `tests/vectors/frost-secp256k1-sha256.json` from the module cache into this directory.
3. Run `go test ./internal/mpc/frostsecp256k1 -count=1`.
