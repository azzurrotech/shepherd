// Package keys supplies key material to the rest of shepherd and to the
// browser JavaScript software (vici/veni/vidi/vini) that shepherd protects.
//
// JavaScript consumers load the key over HTTPS, then feed it to WebCrypto,
// e.g.:
//
//	const {key, ivLength} = await (await fetch('/api/keys/javascript?scope=chat')).json();
//	const k = await crypto.subtle.importKey('raw', base64ToBuf(key), 'AES-GCM', false, ['encrypt','decrypt']);
//
// Deterministic "derived" keys are produced with an HMAC-SHA256 KDF over the
// master secret plus a purpose and a scope, so a scope always maps to the same
// key without the server storing anything.
package keys

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"time"
)

// ErrKeyTooShort is returned when a derived key does not meet the requested
// byte length.
var ErrKeyTooShort = errors.New("derived key material too short")

// Classic AES-GCM parameters for the JavaScript key endpoint.
const (
	AESAlgorithm = "AES-GCM"
	AESIVLength  = 12 // bytes, the WebCrypto default
	AESKeyBytes  = 32 // 256-bit
)

// Member key purposes (namespaced so scopes cannot collide across uses).
const (
	PurposeEncrypt = "encrypt"
	PurposeSign    = "sign"
)

// JSCryptoKey is the JSON document /api/keys/javascript returns.
type JSCryptoKey struct {
	Algorithm   string    `json:"algorithm"`
	Format      string    `json:"format"`
	Usage       string    `json:"usage"`
	Key         string    `json:"key"` // base64 (raw WebCrypto format)
	KDF         string    `json:"kdf"`
	Scope       string    `json:"scope"`
	IVLength    int       `json:"iv_length"`
	GeneratedAt time.Time `json:"generated_at"`
}

// RandomBytes returns n cryptographically secure random bytes.
func RandomBytes(n int) ([]byte, error) {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return nil, err
	}
	return b, nil
}

// RandomID returns a 128-bit random identifier encoded in lowercase hex.
func RandomID() (string, error) {
	b, err := RandomBytes(16)
	if err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}

// Derive deterministically derives a key from the master secret for a purpose
// and scope. The output is HMAC-SHA256(master, purpose + "\x00" + scope).
func Derive(master []byte, purpose, scope string) []byte {
	mac := hmac.New(sha256.New, master)
	mac.Write([]byte(purpose))
	mac.Write([]byte{0})
	mac.Write([]byte(scope))
	return mac.Sum(nil)
}

// JSDerivedAES returns a deterministic AES-256-GCM key for WebCrypto, derived
// from the master secret and the given scope.
func JSDerivedAES(master []byte, scope string) (JSCryptoKey, error) {
	raw := Derive(master, PurposeEncrypt, scope)
	if len(raw) < AESKeyBytes {
		return JSCryptoKey{}, ErrKeyTooShort
	}
	return JSCryptoKey{
		Algorithm:   AESAlgorithm,
		Format:      "raw",
		Usage:       "encrypt/decrypt",
		Key:         base64.StdEncoding.EncodeToString(raw[:AESKeyBytes]),
		KDF:         "HMAC-SHA256",
		Scope:       scope,
		IVLength:    AESIVLength,
		GeneratedAt: time.Now().UTC(),
	}, nil
}

// JSRandomAES returns a fresh random AES-256-GCM key for WebCrypto.
func JSRandomAES(scope string) (JSCryptoKey, error) {
	raw, err := RandomBytes(AESKeyBytes)
	if err != nil {
		return JSCryptoKey{}, err
	}
	return JSCryptoKey{
		Algorithm:   AESAlgorithm,
		Format:      "raw",
		Usage:       "encrypt/decrypt",
		Key:         base64.StdEncoding.EncodeToString(raw),
		KDF:         "random",
		Scope:       scope,
		IVLength:    AESIVLength,
		GeneratedAt: time.Now().UTC(),
	}, nil
}

// JSHMAC returns a deterministic HMAC-SHA256 key for WebCrypto (used to
// authenticate messages from JavaScript).
func JSHMAC(master []byte, scope string) (JSCryptoKey, error) {
	raw := Derive(master, PurposeSign, scope)
	return JSCryptoKey{
		Algorithm:   "HMAC",
		Format:      "raw",
		Usage:       "sign/verify",
		Key:         base64.StdEncoding.EncodeToString(raw),
		KDF:         "HMAC-SHA256",
		Scope:       scope,
		IVLength:    0,
		GeneratedAt: time.Now().UTC(),
	}, nil
}
