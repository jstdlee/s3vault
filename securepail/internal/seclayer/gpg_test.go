package seclayer

import (
	"bytes"
	"context"
	"errors"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func realGPG(t *testing.T) *GPG {
	t.Helper()
	if _, err := exec.LookPath("gpg"); err != nil {
		t.Skip("gpg not installed")
	}
	// Isolated GNUPGHOME so the test never touches the user's keyring.
	t.Setenv("GNUPGHOME", shortTemp(t))
	g, err := Locate(context.Background(), "auto")
	if err != nil {
		t.Fatalf("Locate: %v", err)
	}
	return g
}

// shortTemp: gpg-agent sockets need a short path.
func shortTemp(t *testing.T) string {
	d, err := os.MkdirTemp("", "g")
	if err != nil {
		t.Fatal(err)
	}
	os.Chmod(d, 0o700)
	t.Cleanup(func() {
		exec.Command("gpgconf", "--kill", "gpg-agent").Run()
		os.RemoveAll(d)
	})
	return d
}

func TestParseVersion(t *testing.T) {
	v, maj, min, ok := ParseVersion("gpg (GnuPG) 2.4.4\nlibgcrypt 1.10")
	if !ok || v != "2.4.4" || maj != 2 || min != 4 {
		t.Fatalf("got %q %d %d %v", v, maj, min, ok)
	}
	if _, _, _, ok := ParseVersion("nonsense"); ok {
		t.Fatal("parsed nonsense")
	}
	if VersionOK(2, 1) || !VersionOK(2, 2) || !VersionOK(3, 0) {
		t.Fatal("VersionOK")
	}
}

func TestLocateMissingAndOld(t *testing.T) {
	none := func(string) (string, error) { return "", errors.New("no") }
	if _, err := LocateWith(context.Background(), "auto", none, nil); !errors.Is(err, ErrNoGPG) {
		t.Fatalf("want ErrNoGPG, got %v", err)
	}
	look := func(n string) (string, error) { return "/x/" + n, nil }
	run := func(ctx context.Context, name string, args []string, in io.Reader, out io.Writer) (string, error) {
		out.Write([]byte("gpg (GnuPG) 2.0.22\n"))
		return "", nil
	}
	g, err := LocateWith(context.Background(), "auto", look, run)
	if err == nil || !strings.Contains(err.Error(), "too old") || g == nil {
		t.Fatalf("want too old, got %v", err)
	}
}

func TestClassifyAndIntegrity(t *testing.T) {
	if err := Classify(errors.New("x"), "[GNUPG:] DECRYPTION_FAILED\n[GNUPG:] BAD_PASSPHRASE"); !errors.Is(err, ErrBadPassphrase) {
		t.Fatalf("got %v", err)
	}
	if err := Classify(errors.New("x"), "[GNUPG:] BADMDC"); !errors.Is(err, ErrTampered) {
		t.Fatalf("got %v", err)
	}
	if err := CheckIntegrity("[GNUPG:] DECRYPTION_OKAY\n"); !errors.Is(err, ErrTampered) {
		t.Fatalf("no MDC must be refused: %v", err)
	}
	if err := CheckIntegrity("[GNUPG:] GOODMDC\n"); !errors.Is(err, ErrNotEncrypted) {
		t.Fatalf("no DECRYPTION_OKAY must be refused: %v", err)
	}
	if err := CheckIntegrity("[GNUPG:] DECRYPTION_INFO 2 9 0\n[GNUPG:] DECRYPTION_OKAY\n[GNUPG:] GOODMDC\n"); err != nil {
		t.Fatal(err)
	}
	if err := CheckIntegrity("[GNUPG:] DECRYPTION_INFO 0 9 2\n[GNUPG:] DECRYPTION_OKAY\n"); err != nil {
		t.Fatalf("AEAD must be accepted: %v", err)
	}
}

func TestRoundTripGeneratedKey(t *testing.T) {
	g := realGPG(t)
	ctx := context.Background()
	key, err := GenerateKey()
	if err != nil || !IsGeneratedKey(key) || StrongS2K(key) {
		t.Fatalf("key %q %v", key, err)
	}
	dir := t.TempDir()
	plain := bytes.Repeat([]byte("hello securePail\n"), 5000)
	in := filepath.Join(dir, "in")
	os.WriteFile(in, plain, 0o600)
	var ct bytes.Buffer
	if err := g.Encrypt(ctx, in, &ct, key, StrongS2K(key), false); err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(ct.Bytes(), []byte("hello")) {
		t.Fatal("ciphertext leaks plaintext")
	}
	cf := filepath.Join(dir, "ct")
	os.WriteFile(cf, ct.Bytes(), 0o600)
	var out bytes.Buffer
	if err := g.Decrypt(ctx, cf, &out, key); err != nil || !bytes.Equal(out.Bytes(), plain) {
		t.Fatalf("decrypt: %v", err)
	}
	var bad bytes.Buffer
	if err := g.Decrypt(ctx, cf, &bad, key+"x"); !errors.Is(err, ErrBadPassphrase) || bad.Len() != 0 {
		t.Fatalf("want bad passphrase with no output, got %v (%d bytes)", err, bad.Len())
	}
}

func TestTamperedAndPlainRefused(t *testing.T) {
	g := realGPG(t)
	ctx := context.Background()
	ct, err := g.EncryptBytes(ctx, []byte("secret data secret data"), "k-k-k-k-k-k-k-k", false)
	if err != nil {
		t.Fatal(err)
	}
	tam := append([]byte(nil), ct...)
	tam[len(tam)-5] ^= 0xff
	if _, err := g.DecryptBytes(ctx, tam, "k-k-k-k-k-k-k-k", 1<<20); err == nil {
		t.Fatal("tampered ciphertext decrypted")
	}
	// Not OpenPGP at all.
	if _, err := g.DecryptBytes(ctx, []byte("just text"), "x", 1<<20); err == nil {
		t.Fatal("plain text decrypted")
	}
	// Size cap.
	if _, err := g.DecryptBytes(ctx, ct, "k-k-k-k-k-k-k-k", 3); err == nil {
		t.Fatal("size cap ignored")
	}
}

func TestWrapUnwrapKey(t *testing.T) {
	g := realGPG(t)
	ctx := context.Background()
	key, _ := GenerateKey()
	w, err := g.WrapKey(ctx, key, "correct horse battery staple 42")
	if err != nil {
		t.Fatal(err)
	}
	got, err := g.UnwrapKey(ctx, w, "correct horse battery staple 42")
	if err != nil || got != key {
		t.Fatalf("got %q %v", got, err)
	}
	if _, err := g.UnwrapKey(ctx, w, "wrong password wrong"); !errors.Is(err, ErrBadPassphrase) {
		t.Fatalf("want bad passphrase, got %v", err)
	}
}

func TestPasswordStrength(t *testing.T) {
	for _, pw := range []string{"short", "password123456789", "aaaaaaaaaaaaaaaa", "abcd1234efgh5678"} {
		if CheckPassword(pw).Acceptable {
			t.Errorf("%q accepted", pw)
		}
	}
	if s := CheckPassword("vT9#kQ2!mZx7$pLw4Rn"); !s.Acceptable {
		t.Errorf("strong password rejected: %+v", s)
	}
}
