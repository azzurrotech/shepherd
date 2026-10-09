# keys — key material for shepherd and its browser software

`azzurrotech/shepherd/keys` supplies key material to the rest of shepherd and
to the browser JavaScript software (vici/veni/vidi/vini) that shepherd
protects. It provides a CSPRNG wrapper, a deterministic HMAC-SHA256 KDF, and
hand-built JSON documents that a browser can feed straight to WebCrypto.

## Overview

The package lives in the `azzurrotech/shepherd` module. Server mode exposes it
through `GET /api/keys/javascript?scope=…&usage=…` (`server.go`), which calls
`(*middleware.Shepherd).JSCryptoKey`; that method delegates to
`JSDerivedAES`/`JSHMAC` here. `RandomBytes` is also used by `main.go` to
generate an ephemeral master secret and is re-exported in spirit by the
`token` package.

JavaScript consumers load a key over HTTPS and import it:

```js
const {key, ivLength} = await (await fetch('/api/keys/javascript?scope=chat')).json();
const k = await crypto.subtle.importKey('raw', base64ToBuf(key), 'AES-GCM', false, ['encrypt','decrypt']);
```

Deterministic keys are produced with an HMAC-SHA256 KDF over the master secret
plus a purpose and a scope, so a scope always maps to the same key while the
server stores nothing.

## Public API

### Errors and constants

- `var ErrKeyTooShort` — derived material shorter than requested.
- `const AESAlgorithm = "AES-GCM"` — algorithm advertised to WebCrypto.
- `const AESIVLength = 12` — IV length in bytes (WebCrypto default).
- `const AESKeyBytes = 32` — 256-bit AES key size.
- `const PurposeEncrypt = "encrypt"` — KDF purpose for AES keys.
- `const PurposeSign = "sign"` — KDF purpose for HMAC keys.

### Types

- `type JSCryptoKey struct` — the JSON document returned by
  `/api/keys/javascript`:
  `Algorithm string` (`algorithm`), `Format string` (`format`),
  `Usage string` (`usage`), `Key string` (`key`, base64 raw format),
  `KDF string` (`kdf`), `Scope string` (`scope`), `IVLength int`
  (`iv_length`), `GeneratedAt time.Time` (`generated_at`).

### Functions

- `func RandomBytes(n int) ([]byte, error)` — `n` cryptographically secure
  random bytes (`crypto/rand`).
- `func RandomID() (string, error)` — 128-bit random identifier in lowercase
  hex.
- `func Derive(master []byte, purpose, scope string) []byte` — deterministic
  `HMAC-SHA256(master, purpose || 0x00 || scope)`.
- `func JSDerivedAES(master []byte, scope string) (JSCryptoKey, error)` —
  deterministic AES-256-GCM key (`KDF: "HMAC-SHA256"`).
- `func JSRandomAES(scope string) (JSCryptoKey, error)` — fresh random
  AES-256-GCM key (`KDF: "random"`).
- `func JSHMAC(master []byte, scope string) (JSCryptoKey, error)` —
  deterministic HMAC-SHA256 key (`Usage: "sign/verify"`, `IVLength: 0`).

## Usage

```go
master := []byte("0123456789abcdef0123456789abcdef")

aes, err := keys.JSDerivedAES(master, "chat")   // stable per scope
if err != nil {
    log.Fatal(err)
}
log.Println(aes.Algorithm, aes.IVLength, aes.KDF) // AES-GCM 12 HMAC-SHA256

mac, _ := keys.JSHMAC(master, "chat")           // deterministic sign key
_ = mac.Key
```

## Configuration, inputs, defaults and limits

- **Derivation input**: `master` secret + `purpose` (namespace) + `scope`,
  joined with a `0x00` separator inside `Derive`. The separator keeps
  `("ab","c")` distinct from `("a","bc")`.
- **Purpose namespacing**: encrypt and sign keys for the same scope are
  independent because `PurposeEncrypt`/`PurposeSign` differ.
- **AES output**: exactly `AESKeyBytes` (32) bytes, base64 standard-encoded;
  `JSDerivedAES` returns `ErrKeyTooShort` if the derived material is somehow
  shorter than 32 bytes (HMAC-SHA256 always yields 32, so this is defensive).
- **Derived key fields**: `Format: "raw"`, `Usage: "encrypt/decrypt"`,
  `IVLength: 12`, `GeneratedAt` set to `time.Now().UTC()` on every call.
- **Random key fields**: same shape, `KDF: "random"`, key from `crypto/rand`;
  each call returns a different key.
- **No persistence**: nothing is stored; derived keys are reproducible from the
  master secret, random keys are not.

## Testing

From the module root `/home/matthew/Projects/Platform/stenella/atp/shepherd`:

```sh
go test ./keys/
go test -race ./keys/
```

`keys_test.go` verifies that `Derive` is deterministic per `(purpose, scope)`
and changes with scope or master secret, that `JSDerivedAES` yields stable
base64 that decodes to 32 bytes with `AES-GCM`/`IVLength == 12`, that
`JSRandomAES` differs per call, and that `JSHMAC` equals the expected
`HMAC-SHA256(master, purpose\x00scope)`.

## Design notes and invariants

- `Derive` is pure and deterministic: same inputs always produce the same
  bytes, which is what makes storage-free key agreement possible.
- Randomness is exclusively `crypto/rand` (`RandomBytes`); no `math/rand`.
- The package never inspects or logs the master secret.
- Keys are returned as base64 of raw bytes, matching WebCrypto's `raw` import
  format; `IVLength` tells the browser which IV size to pair with AES-GCM.
