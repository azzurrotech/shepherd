package keys

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"testing"
)

func TestDeriveDeterministic(t *testing.T) {
	master := []byte("0123456789abcdef0123456789abcdef")
	a := Derive(master, PurposeEncrypt, "chat")
	b := Derive(master, PurposeEncrypt, "chat")
	if !bytes.Equal(a, b) {
		t.Fatalf("derive must be deterministic")
	}
	c := Derive(master, PurposeEncrypt, "other")
	if bytes.Equal(a, c) {
		t.Fatalf("derive must vary by scope")
	}
	d := Derive([]byte("0123456789abcdef0123456789abcdee"), PurposeEncrypt, "chat")
	if bytes.Equal(a, d) {
		t.Fatalf("derive must vary by master secret")
	}
}

func TestJSDerivedAES(t *testing.T) {
	master := []byte("0123456789abcdef0123456789abcdef")
	k1, err := JSDerivedAES(master, "chat")
	if err != nil {
		t.Fatalf("JSDerivedAES: %v", err)
	}
	raw, err := base64.StdEncoding.DecodeString(k1.Key)
	if err != nil {
		t.Fatalf("key not valid base64: %v", err)
	}
	if len(raw) != AESKeyBytes {
		t.Fatalf("expected 32-byte key, got %d", len(raw))
	}
	if k1.Algorithm != "AES-GCM" || k1.IVLength != 12 {
		t.Fatalf("wrong params: %+v", k1)
	}
	k2, _ := JSDerivedAES(master, "chat")
	if k1.Key != k2.Key {
		t.Fatalf("derived key must be stable per scope")
	}
}

func TestJSRandomAES(t *testing.T) {
	k1, err := JSRandomAES("session")
	if err != nil {
		t.Fatalf("JSRandomAES: %v", err)
	}
	k2, _ := JSRandomAES("session")
	if k1.Key == k2.Key {
		t.Fatalf("random keys must differ")
	}
	raw, _ := base64.StdEncoding.DecodeString(k1.Key)
	if len(raw) != 32 {
		t.Fatalf("expected 32-byte random key")
	}
}

func TestJSHMAC(t *testing.T) {
	master := []byte("0123456789abcdef0123456789abcdef")
	h, err := JSHMAC(master, "chat")
	if err != nil {
		t.Fatalf("JSHMAC: %v", err)
	}
	raw, _ := base64.StdEncoding.DecodeString(h.Key)
	mac := hmac.New(sha256.New, master)
	mac.Write([]byte(PurposeSign))
	mac.Write([]byte{0})
	mac.Write([]byte("chat"))
	if !hmac.Equal(raw, mac.Sum(nil)) {
		t.Fatalf("HMAC key must equal HMAC-SHA256(master, purpose\\x00scope)")
	}
}
