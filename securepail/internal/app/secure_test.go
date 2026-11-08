package app

import (
	"bytes"
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/jstdlee/securePail/internal/rules"
)

func needGPG(t *testing.T) {
	t.Helper()
	if _, err := exec.LookPath("gpg"); err != nil {
		t.Skip("gpg not installed")
	}
	home, err := os.MkdirTemp("", "g")
	if err != nil {
		t.Fatal(err)
	}
	os.Chmod(home, 0o700)
	t.Setenv("GNUPGHOME", home)
	t.Cleanup(func() {
		exec.Command("gpgconf", "--kill", "gpg-agent").Run()
		os.RemoveAll(home)
	})
}

func TestSecureLayerRoundTrip(t *testing.T) {
	needGPG(t)
	const content = "top secret: the quick brown fox jumps over the lazy dog\n"
	for _, tc := range []struct {
		name   string
		method string
		comp   *rules.Compression
		key    string
	}{
		{"gpg", "gpg", nil, "d.txt.gpg"},
		{"gzip then gpg", "gpg", &rules.Compression{Method: "gzip", Level: -1}, "d.txt.gpg"},
		{"zip then gpg", "gpg", &rules.Compression{Method: "zip", Level: -1}, "d.txt.zip.gpg"},
		{"aesgcm", "aesgcm", nil, "d.txt.spe"},
		{"gzip then aesgcm", "aesgcm", &rules.Compression{Method: "gzip", Level: -1}, "d.txt.spe"},
		{"zip then aesgcm", "aesgcm", &rules.Compression{Method: "zip", Level: -1}, "d.txt.zip.spe"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			e := newTrEnv(t)
			if err := e.s.GenerateSecureKey("vk"); err != nil {
				t.Fatal(err)
			}
			if err := e.s.SaveUploadRules([]rules.UploadRule{{Name: "s", Compression: tc.comp,
				Secure: &rules.Secure{Method: tc.method, KeyRef: "vk"}}}); err != nil {
				t.Fatal(err)
			}
			src := filepath.Join(t.TempDir(), "d.txt")
			trWrite(t, src, []byte(content))
			before := trSpoolFiles(t)
			trExpect(t, e.upload(UploadRequest{Dest: e.loc("b", ""), Paths: []string{src}}), StatusSucceeded)
			if after := trSpoolFiles(t); after != before {
				t.Errorf("spool files before %d after %d", before, after)
			}
			raw, ok := e.srv.Object("b", tc.key)
			if !ok {
				t.Fatalf("object %q missing; have %v", tc.key, e.srv.Buckets())
			}
			if bytes.Contains(raw, []byte("quick brown fox")) {
				t.Fatal("plaintext visible in the stored object")
			}
			info, err := e.s.Head(testCtx(t), e.loc("b", ""), tc.key, "")
			if err != nil {
				t.Fatal(err)
			}
			if info.ContentType != "application/octet-stream" {
				t.Errorf("Content-Type = %q", info.ContentType)
			}
			for _, h := range info.Headers {
				if strings.EqualFold(h.Name, "Content-Encoding") && h.Value != "" {
					t.Errorf("Content-Encoding %q must not be set on ciphertext", h.Value)
				}
			}

			out := t.TempDir()
			trExpect(t, e.download(DownloadRequest{Source: e.loc("b", ""), Keys: []string{tc.key}, DestDir: out,
				Decode: DecodeAuto, SecureKeyRef: "vk"}), StatusSucceeded)
			got := trRead(t, filepath.Join(out, filepath.FromSlash(tc.key)))
			if got != content {
				t.Fatalf("decrypted content = %q", got)
			}
		})
	}
}

func TestSecureLayerFailuresLeaveNothing(t *testing.T) {
	needGPG(t)
	e := newTrEnv(t)
	if err := e.s.GenerateSecureKey("good"); err != nil {
		t.Fatal(err)
	}
	if err := e.s.GenerateSecureKey("other"); err != nil {
		t.Fatal(err)
	}
	if err := e.s.SaveUploadRules([]rules.UploadRule{{Name: "s", Secure: &rules.Secure{Method: "gpg", KeyRef: "good"}}}); err != nil {
		t.Fatal(err)
	}
	src := filepath.Join(t.TempDir(), "d.txt")
	trWrite(t, src, []byte("payload"))
	trExpect(t, e.upload(UploadRequest{Dest: e.loc("b", ""), Paths: []string{src}}), StatusSucceeded)

	for name, req := range map[string]DownloadRequest{
		"no key":    {Decode: DecodeAuto},
		"wrong key": {Decode: DecodeAuto, SecureKeyRef: "other"},
	} {
		out := t.TempDir()
		req.Source, req.Keys, req.DestDir = e.loc("b", ""), []string{"d.txt.gpg"}, out
		failedErr(t, e.download(req))
		if m, _ := os.ReadDir(out); len(m) != 0 {
			t.Errorf("%s: left files behind: %v", name, m)
		}
	}
	// Without decode the ciphertext is saved untouched.
	out := t.TempDir()
	trExpect(t, e.download(DownloadRequest{Source: e.loc("b", ""), Keys: []string{"d.txt.gpg"}, DestDir: out}), StatusSucceeded)
	if strings.Contains(trRead(t, filepath.Join(out, "d.txt.gpg")), "payload") {
		t.Fatal("raw download is not ciphertext")
	}
}

func TestSecureLayerNeedsKeyAndGPG(t *testing.T) {
	needGPG(t)
	e := newTrEnv(t)
	if err := e.s.SaveUploadRules([]rules.UploadRule{{Name: "s", Secure: &rules.Secure{Method: "gpg", KeyRef: "nokey"}}}); err != nil {
		t.Fatal(err)
	}
	src := filepath.Join(t.TempDir(), "d.txt")
	trWrite(t, src, []byte("payload"))
	failedErr(t, e.upload(UploadRequest{Dest: e.loc("b", ""), Paths: []string{src}}))
	if _, ok := e.srv.Object("b", "d.txt"); ok {
		t.Fatal("a plain copy was uploaded despite the failed secure layer")
	}
	if _, ok := e.srv.Object("b", "d.txt.gpg"); ok {
		t.Fatal("object uploaded without a key")
	}

	// gpg missing: fail closed, never upload plaintext.
	if err := e.s.GenerateSecureKey("nokey"); err != nil {
		t.Fatal(err)
	}
	t.Setenv("SECUREPAIL_GPG", "/nonexistent/gpg")
	failedErr(t, e.upload(UploadRequest{Dest: e.loc("b", ""), Paths: []string{src}}))
	if _, ok := e.srv.Object("b", "d.txt"); ok {
		t.Fatal("plaintext uploaded although gpg is missing")
	}
}

func TestSecureKeyBackupRestore(t *testing.T) {
	needGPG(t)
	e := newTrEnv(t)
	ctx := context.Background()
	if err := e.s.GenerateSecureKey("vk"); err != nil {
		t.Fatal(err)
	}
	if err := e.s.GenerateSecureKey("vk"); err == nil {
		t.Fatal("an existing key was replaced")
	}
	const pw = "vT9#kQ2!mZx7$pLw4Rn"
	if _, err := e.s.ExportSecureKey(ctx, "vk", "weak", KeyFileGPG); err == nil {
		t.Fatal("weak backup password accepted")
	}
	wrapped, err := e.s.ExportSecureKey(ctx, "vk", pw, KeyFileGPG)
	if err != nil {
		t.Fatal(err)
	}
	orig, _ := e.s.secureKey(ctx, "vk")
	if bytes.Contains(wrapped, []byte(orig)) {
		t.Fatal("key visible in backup")
	}
	if err := e.s.ImportSecureKey(ctx, "copy", wrapped, "wrong wrong wrong wrong"); err == nil {
		t.Fatal("wrong password imported")
	}
	if err := e.s.ImportSecureKey(ctx, "copy", wrapped, pw); err != nil {
		t.Fatal(err)
	}
	if got, _ := e.s.secureKey(ctx, "copy"); got != orig {
		t.Fatal("restored key differs")
	}
	if err := e.s.SetSecurePassphrase("p", "short"); err == nil {
		t.Fatal("weak passphrase accepted")
	}
}

func TestReadinessRequiresGPGOnlyWithLayer(t *testing.T) {
	needGPG(t)
	e := newTrEnv(t)
	r := e.s.Readiness(context.Background())
	for _, it := range r.Items {
		if it.Required && it.ID == "gpg" {
			t.Fatal("gpg must not be required without a GPG layer")
		}
	}
	if err := e.s.SaveUploadRules([]rules.UploadRule{{Name: "s", Secure: &rules.Secure{Method: "gpg", KeyRef: "k"}}}); err != nil {
		t.Fatal(err)
	}
	r = e.s.Readiness(context.Background())
	found := false
	for _, it := range r.Items {
		if it.ID == "gpg" {
			found = it.Required
		}
	}
	if !found {
		t.Fatal("gpg must be required with an enabled GPG layer")
	}
}

// failedErr returns the error text of the first failed task and fails the test
// when none failed.
func failedErr(t *testing.T, tasks []Task) string {
	t.Helper()
	for _, tk := range tasks {
		if tk.Status == StatusFailed {
			return tk.Err
		}
	}
	t.Fatalf("no task failed: %+v", tasks)
	return ""
}

func TestPortableSuiteNeedsNoGPG(t *testing.T) {
	// No gpg at all: the portable suite must still work end to end.
	t.Setenv("SECUREPAIL_GPG", "/nonexistent/gpg")
	e := newTrEnv(t)
	if err := e.s.GenerateSecureKey("vk"); err != nil {
		t.Fatal(err)
	}
	if err := e.s.SaveUploadRules([]rules.UploadRule{{Name: "s", Secure: &rules.Secure{Method: "aesgcm", KeyRef: "vk"}}}); err != nil {
		t.Fatal(err)
	}
	src := filepath.Join(t.TempDir(), "big.bin")
	data := trBigData(2<<20 + 5)
	trWrite(t, src, data)
	trExpect(t, e.upload(UploadRequest{Dest: e.loc("b", ""), Paths: []string{src}}), StatusSucceeded)
	out := t.TempDir()
	trExpect(t, e.download(DownloadRequest{Source: e.loc("b", ""), Keys: []string{"big.bin.spe"}, DestDir: out,
		Decode: DecodeAuto, SecureKeyRef: "vk"}), StatusSucceeded)
	if trRead(t, filepath.Join(out, "big.bin.spe")) != string(data) {
		t.Fatal("round trip differs")
	}
	// gpg is not required, so the readiness check passes without it.
	if r := e.s.Readiness(context.Background()); !r.Ready {
		t.Fatalf("readiness: %s", r.Render())
	}
	// Tamper with the stored object: download must refuse and save nothing.
	raw, _ := e.srv.Object("b", "big.bin.spe")
	raw = append([]byte(nil), raw...)
	raw[len(raw)/2] ^= 1
	e.srv.PutObject("b", "big.bin.spe", raw, "application/octet-stream", map[string]string{secureMetaKey: "aesgcm"})
	out = t.TempDir()
	failedErr(t, e.download(DownloadRequest{Source: e.loc("b", ""), Keys: []string{"big.bin.spe"}, DestDir: out,
		Decode: DecodeAuto, SecureKeyRef: "vk"}))
	if m, _ := os.ReadDir(out); len(m) != 0 {
		t.Fatalf("left files behind: %v", m)
	}
}

func TestPortableSuiteRejectsTypedPassphrase(t *testing.T) {
	e := newTrEnv(t)
	if err := e.s.SetSecurePassphrase("pp", "vT9#kQ2!mZx7$pLw4Rn"); err != nil {
		t.Fatal(err)
	}
	if err := e.s.SaveUploadRules([]rules.UploadRule{{Name: "s", Secure: &rules.Secure{Method: "aesgcm", KeyRef: "pp"}}}); err != nil {
		t.Fatal(err)
	}
	src := filepath.Join(t.TempDir(), "d.txt")
	trWrite(t, src, []byte("x"))
	if msg := failedErr(t, e.upload(UploadRequest{Dest: e.loc("b", ""), Paths: []string{src}})); !strings.Contains(msg, "generated key") {
		t.Fatalf("message: %s", msg)
	}
}

func TestPortableKeyBackupAndRecovery(t *testing.T) {
	e := newTrEnv(t) // no gpg needed for the key file format
	ctx := context.Background()
	if err := e.s.GenerateSecureKey("vk"); err != nil {
		t.Fatal(err)
	}
	const pw = "vT9#kQ2!mZx7$pLw4Rn"
	kf, err := e.s.ExportSecureKey(ctx, "vk", pw, KeyFileJSON)
	if err != nil {
		t.Fatal(err)
	}
	if err := e.s.ImportSecureKey(ctx, "copy", kf, pw); err != nil {
		t.Fatal(err)
	}
	rec, err := e.s.SecureRecoveryKey(ctx, "vk")
	if err != nil {
		t.Fatal(err)
	}
	if err := e.s.ImportSecureKey(ctx, "fromrec", []byte(rec), ""); err != nil {
		t.Fatal(err)
	}
	a, _ := e.s.secureKey(ctx, "vk")
	for _, r := range []string{"copy", "fromrec"} {
		if b, _ := e.s.secureKey(ctx, r); a != b {
			t.Fatalf("%s differs", r)
		}
	}
	if err := e.s.ImportSecureKey(ctx, "bad", kf, "wrong wrong wrong"); err == nil {
		t.Fatal("wrong password imported")
	}
}
