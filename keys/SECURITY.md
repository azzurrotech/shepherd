# keys — Security

This document describes the security properties of
`azzurrotech/shepherd/keys` as implemented. It makes no claims beyond the code.

## Assets protected

- The **master secret** — the root input to every deterministic key.
- **Key separation** between purposes (encryption vs. signing) and between
  scopes.
- **Randomness quality** for generated secrets, identifiers and one-off keys.

## Threat model

In scope:

- Deriving one scope's key must not reveal another scope's key, and deriving an
  encryption key must not reveal the signing key for the same scope.
- Generated key material and identifiers must be unpredictable (not guessable,
  not seeded from time or `math/rand`).
- A scope name collision across purposes must not silently reuse a key.

Out of scope:

- Confidentiality of keys after they leave this package. Delivering a derived
  key to a browser is the caller's responsibility and should happen over HTTPS.
- Protecting the master secret at rest or in memory; that is a deployment
  concern.
- Encrypting data. This package produces keys; it does not perform AES or HMAC
  operations on application data.

## Mitigations actually implemented

- **Domain-separated KDF**: `Derive` computes
  `HMAC-SHA256(master, purpose || 0x00 || scope)`. The `0x00` separator prevents
  concatenation ambiguity, and the purpose string namespaces uses.
- **Purpose namespacing**: `JSDerivedAES` uses `PurposeEncrypt`; `JSHMAC` uses
  `PurposeSign`, so the same scope yields distinct keys per purpose.
- **CSPRNG only**: `RandomBytes` uses `crypto/rand`; `RandomID` draws 16 bytes
  from it and hex-encodes. `JSRandomAES` keys are fresh CSPRNG output.
- **Length validation**: `JSDerivedAES` returns `ErrKeyTooShort` if the derived
  material is under `AESKeyBytes`, rather than emitting a short key.
- **Explicit parameters**: keys advertise `Format: "raw"` and the correct
  `IVLength`, reducing the chance of a browser pairing AES-GCM with the wrong
  IV size.

## Honest limits / non-claims

- **Anyone with the master secret can derive every deterministic key.** These
  keys are pure KDF output, not independently stored secrets.
- **A browser must still receive its key over the wire.** The package does not
  authenticate or encrypt that delivery; use TLS and an admin/authorization
  check (server mode requires the admin token for `/api/keys/javascript`).
- **`JSRandomAES` keys are not reproducible.** If the returned key is lost
  before use, it cannot be re-derived; the caller must persist or re-request it.
- **No key rotation primitive.** Rotating the master secret changes every
  derived key at once and invalidates existing ciphertext unless re-wrapped by
  the application.
- **`GeneratedAt` is informational.** It is set per call and is not part of any
  signature; treat it as a timestamp hint, not a guarantee.
- **`ErrKeyTooShort` is defensive.** HMAC-SHA256 always produces 32 bytes, so
  the check should not trigger in practice.

## Dependencies

Standard library only: `crypto/hmac`, `crypto/rand`, `crypto/sha256`,
`encoding/base64`, `encoding/hex`, `errors`, `time`. No third-party packages.

## Reporting

Report security issues privately to **security@azzurro.tech**. Do not open a
public issue. Include the shepherd version, the mode (server/middleware), and a
minimal reproduction.
