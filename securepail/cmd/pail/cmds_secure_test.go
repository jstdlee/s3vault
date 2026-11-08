package main

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func cliGPG(t *testing.T) {
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

func TestDoctorReportsReadyAndMissing(t *testing.T) {
	cliGPG(t)
	h := newHarness(t)
	r := h.want(h.run("doctor", "--require-gpg"), 0)
	for _, s := range []string{"GnuPG (gpg)", "round trip", "Ready."} {
		if !strings.Contains(r.out, s) {
			t.Errorf("missing %q in:\n%s", s, r.out)
		}
	}
	// JSON form.
	r = h.want(h.run("--json", "doctor", "--require-gpg"), 0)
	ev := jsonLines(t, r.out)
	if last := ev[len(ev)-1]; last["type"] != "summary" || last["ok"] != true {
		t.Fatalf("json: %s", r.out)
	}

	t.Setenv("SECUREPAIL_GPG", "/nonexistent/gpg")
	r = h.want(h.run("doctor", "--require-gpg"), 1)
	if !strings.Contains(r.out, "[FAIL]") || !strings.Contains(r.out, "Install GnuPG") {
		t.Fatalf("want a failure with an install hint:\n%s", r.out)
	}
	// Without a GPG layer the same machine is still ready.
	h.want(h.run("doctor"), 0)
}

func TestSecureKeyCommands(t *testing.T) {
	cliGPG(t)
	h := newHarness(t)
	h.want(h.run("secure", "keygen", "vk"), 0)
	if r := h.want(h.run("secure", "keygen", "vk"), 2); !strings.Contains(r.errOut, "already exists") {
		t.Fatalf("overwrite not refused: %s", r.errOut)
	}
	file := filepath.Join(t.TempDir(), "vk.gpg")
	const pw = "vT9#kQ2!mZx7$pLw4Rn"
	h.want(h.runWith(pw+"\n", nil, "secure", "export", "vk", file, "--password-stdin"), 0)
	if r := h.want(h.runWith(pw+"\n", nil, "secure", "export", "vk", file, "--password-stdin"), 2); !strings.Contains(r.errOut, "never overwritten") {
		t.Fatalf("export overwrote: %s", r.errOut)
	}
	h.want(h.runWith(pw+"\n", nil, "secure", "import", "copy", file, "--password-stdin"), 0)
	h.want(h.runWith("nope nope nope nope\n", nil, "secure", "import", "copy2", file, "--password-stdin"), 2)
	h.want(h.runWith("short\n", nil, "secure", "passphrase", "p", "--password-stdin"), 2)
}

func TestSecureSuitesAndPortableKeys(t *testing.T) {
	h := newHarness(t) // no gpg needed
	r := h.want(h.run("secure", "suites"), 0)
	if !strings.Contains(r.out, "AES-256-GCM (portable)") || !strings.Contains(r.out, "GPG (OpenPGP)") {
		t.Fatalf("suites:\n%s", r.out)
	}
	h.want(h.run("secure", "keygen", "vk"), 0)
	file := filepath.Join(t.TempDir(), "vk.json")
	const pw = "vT9#kQ2!mZx7$pLw4Rn"
	h.want(h.runWith(pw+"\n", nil, "secure", "export", "vk", file, "--password-stdin"), 0)
	b, _ := os.ReadFile(file)
	if !strings.Contains(string(b), `"securepail-key"`) {
		t.Fatalf("not a key file: %s", b)
	}
	h.want(h.runWith(pw+"\n", nil, "secure", "import", "copy", file, "--password-stdin"), 0)
	rec := h.want(h.run("secure", "recovery", "vk"), 0)
	h.want(h.run("secure", "import", "viarec", strings.TrimSpace(rec.out)), 0)
}

// A headless machine has no system keychain; keys then live in the encrypted
// vault, which must be unlocked for keygen and doctor even before any key exists.
func TestSecureCommandsUnlockTheVaultBackend(t *testing.T) {
	h := vaultHarness(t)
	r := h.want(h.runWith(vaultTestPW+"\n", nil, "--vault-password-stdin", "secure", "keygen", "vk"), 0)
	noSecretLeak(t, r)
	r = h.want(h.runWith(vaultTestPW+"\n", nil, "--vault-password-stdin", "doctor"), 0)
	if !strings.Contains(r.out, "[ok]   OS key store") {
		t.Fatalf("doctor did not reach the key store:\n%s", r.out)
	}
	// Without the password the failure says how to fix it.
	r = h.want(h.runWith("", nil, "secure", "keygen", "vk2"), 2)
	if !strings.Contains(r.errOut, "--vault-password-stdin") {
		t.Fatalf("message: %s", r.errOut)
	}
}
