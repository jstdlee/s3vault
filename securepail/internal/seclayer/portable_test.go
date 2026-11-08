package seclayer

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"errors"
	"os"
	"strings"
	"testing"
	"time"
)

func TestPortableRoundTripSizes(t *testing.T) {
	key, _ := GenerateKey()
	for _, n := range []int{0, 1, 100, DefaultChunk - 1, DefaultChunk, DefaultChunk + 1, 3*DefaultChunk + 7} {
		plain := make([]byte, n)
		for i := range plain {
			plain[i] = byte(i * 31)
		}
		var ct bytes.Buffer
		if err := EncryptStream(&ct, bytes.NewReader(plain), key); err != nil {
			t.Fatal(err)
		}
		chunks := max(1, (n+DefaultChunk-1)/DefaultChunk)
		if want := headerLen + n + chunks*tagLen; ct.Len() != want {
			t.Errorf("n=%d: ciphertext %d bytes, want %d", n, ct.Len(), want)
		}
		var out bytes.Buffer
		if err := DecryptStream(&out, bytes.NewReader(ct.Bytes()), key); err != nil || !bytes.Equal(out.Bytes(), plain) {
			t.Fatalf("n=%d: %v", n, err)
		}
	}
}

func TestPortableDetectsTamperTruncationAndWrongKey(t *testing.T) {
	key, _ := GenerateKey()
	other, _ := GenerateKey()
	plain := bytes.Repeat([]byte("x"), 2*DefaultChunk+10)
	var ct bytes.Buffer
	if err := EncryptStream(&ct, bytes.NewReader(plain), key); err != nil {
		t.Fatal(err)
	}
	b := ct.Bytes()
	dec := func(data []byte, k string) error { return DecryptStream(&bytes.Buffer{}, bytes.NewReader(data), k) }

	if err := dec(b, other); !errors.Is(err, ErrTampered) {
		t.Errorf("wrong key: %v", err)
	}
	flip := append([]byte(nil), b...)
	flip[len(flip)/2] ^= 1
	if err := dec(flip, key); err == nil {
		t.Error("bit flip accepted")
	}
	hdr := append([]byte(nil), b...)
	hdr[9] ^= 1 // chunk size field is authenticated as AAD
	if err := dec(hdr, key); err == nil {
		t.Error("header change accepted")
	}
	// Truncation at an exact chunk boundary must fail (last-chunk flag).
	cut := headerLen + 1*(DefaultChunk+tagLen)
	if err := dec(b[:cut], key); err == nil {
		t.Error("truncation at a chunk boundary accepted")
	}
	if err := dec(b[:len(b)-1], key); err == nil {
		t.Error("truncated tail accepted")
	}
	// Appended data.
	if err := dec(append(append([]byte(nil), b...), 0), key); err == nil {
		t.Error("appended byte accepted")
	}
	// Not our format, and OpenPGP.
	if err := dec([]byte("hello"), key); !errors.Is(err, ErrNotPortable) {
		t.Errorf("garbage: %v", err)
	}
	// A typed passphrase is not a portable key.
	if err := EncryptStream(&bytes.Buffer{}, strings.NewReader("x"), "a typed passphrase"); err == nil {
		t.Error("passphrase accepted as portable key")
	}
}

func TestPortableFilesDiffer(t *testing.T) {
	key, _ := GenerateKey()
	var a, b bytes.Buffer
	EncryptStream(&a, strings.NewReader("same"), key)
	EncryptStream(&b, strings.NewReader("same"), key)
	if bytes.Equal(a.Bytes(), b.Bytes()) {
		t.Fatal("two encryptions of the same data are identical (salt reused)")
	}
}

func TestKeyFileAndRecovery(t *testing.T) {
	key, _ := GenerateKey()
	kf, err := MakeKeyFile(key, "Pässword-Ünïcode 123", DefaultPBKDF2)
	if err != nil {
		t.Fatal(err)
	}
	if !IsKeyFile(kf) || strings.Contains(string(kf), key[len(keyPrefix):]) {
		t.Fatal("key file malformed or leaks the key")
	}
	got, err := OpenKeyFile(kf, "Pässword-Ünïcode 123")
	if err != nil || got != key {
		t.Fatalf("got %q %v", got, err)
	}
	// NFD-typed password opens the same file (NFC normalisation).
	if got, err := OpenKeyFile(kf, "Pässword-Ünïcode 123"); err != nil || got != key {
		t.Fatalf("NFD password: %v", err)
	}
	if _, err := OpenKeyFile(kf, "wrong"); !errors.Is(err, ErrBadPassphrase) {
		t.Fatalf("wrong password: %v", err)
	}
	if _, err := MakeKeyFile(key, "x", 10); err == nil {
		t.Error("tiny iteration count accepted")
	}
	rec, err := RecoveryString(key)
	if err != nil || len(rec) != 16*4+15 {
		t.Fatalf("recovery %q %v", rec, err)
	}
	back, err := ParseRecovery(strings.ToLower(strings.ReplaceAll(rec, "-", " ")))
	if err != nil || back != key {
		t.Fatalf("recovery parse: %v", err)
	}
	if _, err := ParseRecovery("12-34"); err == nil {
		t.Error("short recovery accepted")
	}
}

// vectors is the file other platforms use to check their implementation.
type vectors struct {
	Description string `json:"description"`
	Key         string `json:"keyHex"`
	Object      struct {
		SaltHex      string `json:"saltHex"`
		ChunkSize    int    `json:"chunkSize"`
		PlaintextHex string `json:"plaintextHex"`
		ObjectB64    string `json:"objectBase64"`
	} `json:"object"`
	KeyFile struct {
		Password string `json:"password"`
		Nonce    string `json:"nonceHex"`
		Salt     string `json:"saltHex"`
		JSON     string `json:"json"`
	} `json:"keyFile"`
}

const vectorPath = "testdata/portable-vectors.json"

func fixedKey() string {
	raw := make([]byte, 32)
	for i := range raw {
		raw[i] = byte(i)
	}
	return keyPrefix + base64.RawURLEncoding.EncodeToString(raw)
}

func makeVectors(t *testing.T) vectors {
	var v vectors
	v.Description = "securePail portable suite known-answer vectors (object format SPE1, key file securepail-key v1)"
	v.Key = "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"
	salt := make([]byte, 16)
	for i := range salt {
		salt[i] = byte(0xA0 + i)
	}
	plain := []byte(strings.Repeat("securePail vector. ", 120)) // 2280 bytes -> 3 chunks of 1024
	var ct bytes.Buffer
	if err := encryptStream(&ct, bytes.NewReader(plain), fixedKey(), salt, 1024); err != nil {
		t.Fatal(err)
	}
	v.Object.SaltHex = "a0a1a2a3a4a5a6a7a8a9aaabacadaeaf"
	v.Object.ChunkSize = 1024
	v.Object.PlaintextHex = bytesHex(plain)
	v.Object.ObjectB64 = base64.StdEncoding.EncodeToString(ct.Bytes())
	nonce := make([]byte, 12)
	ksalt := make([]byte, 16)
	for i := range nonce {
		nonce[i] = byte(0x10 + i)
	}
	for i := range ksalt {
		ksalt[i] = byte(0x50 + i)
	}
	kf, err := makeKeyFile(fixedKey(), "correct horse", 100_000, ksalt, nonce, time.Unix(1_700_000_000, 0))
	if err != nil {
		t.Fatal(err)
	}
	v.KeyFile.Password, v.KeyFile.Nonce, v.KeyFile.Salt, v.KeyFile.JSON = "correct horse", bytesHex(nonce), bytesHex(ksalt), string(kf)
	return v
}

func bytesHex(b []byte) string {
	const d = "0123456789abcdef"
	out := make([]byte, 0, len(b)*2)
	for _, c := range b {
		out = append(out, d[c>>4], d[c&15])
	}
	return string(out)
}

func TestPortableVectors(t *testing.T) {
	want := makeVectors(t)
	if os.Getenv("UPDATE_VECTORS") != "" {
		b, _ := json.MarshalIndent(want, "", "  ")
		if err := os.WriteFile(vectorPath, append(b, '\n'), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	raw, err := os.ReadFile(vectorPath)
	if err != nil {
		t.Fatalf("%v (create it with UPDATE_VECTORS=1)", err)
	}
	var got vectors
	if err := json.Unmarshal(raw, &got); err != nil {
		t.Fatal(err)
	}
	// The committed object decrypts to the committed plaintext...
	obj, _ := base64.StdEncoding.DecodeString(got.Object.ObjectB64)
	var out bytes.Buffer
	if err := DecryptStream(&out, bytes.NewReader(obj), fixedKey()); err != nil || bytesHex(out.Bytes()) != got.Object.PlaintextHex {
		t.Fatalf("committed object does not decrypt: %v", err)
	}
	// ...and the implementation still produces exactly the committed bytes.
	if got.Object.ObjectB64 != want.Object.ObjectB64 || got.KeyFile.JSON != want.KeyFile.JSON {
		t.Fatal("format changed: the committed vectors no longer match (that breaks existing data)")
	}
	if k, err := OpenKeyFile([]byte(got.KeyFile.JSON), got.KeyFile.Password); err != nil || k != fixedKey() {
		t.Fatalf("committed key file: %v", err)
	}
}

// The Swift package carries its own copy of the vectors; they must not drift.
func TestIOSVectorsAreInSync(t *testing.T) {
	a, err := os.ReadFile(vectorPath)
	if err != nil {
		t.Fatal(err)
	}
	b, err := os.ReadFile("../../ios/SecurePailCrypto/Tests/SecurePailCryptoTests/Resources/portable-vectors.json")
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(a, b) {
		t.Fatal("ios/SecurePailCrypto test vectors differ from internal/seclayer/testdata; copy the file over")
	}
}
