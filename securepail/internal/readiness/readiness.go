// Package readiness checks the external components the secure layer depends
// on (gpg, its agent, the OS key store, a writable spool directory) and says
// plainly what works and what does not, with a hint for each problem.
package readiness

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"time"

	"github.com/jstdlee/securePail/internal/seclayer"
)

// Status of one check.
type Status string

// Check outcomes.
const (
	OK   Status = "ok"
	Warn Status = "warn" // works, but something is degraded or not yet needed
	Fail Status = "fail" // does not work
)

// Check IDs.
const (
	IDGPG      = "gpg"
	IDGPGTest  = "gpg-selftest"
	IDAgent    = "gpg-agent"
	IDKeyring  = "keyring"
	IDSpoolDir = "spooldir"
)

// Item is the result of one check.
type Item struct {
	ID       string `json:"id"`
	Name     string `json:"name"`
	Required bool   `json:"required"` // needed by the enabled secure layers
	Status   Status `json:"status"`
	Path     string `json:"path,omitempty"`
	Version  string `json:"version,omitempty"`
	Detail   string `json:"detail"`
	Hint     string `json:"hint,omitempty"`
}

// Report is the full result.
type Report struct {
	Items []Item `json:"items"`
	// Ready is true when no required item failed.
	Ready bool `json:"ready"`
}

// Keyring is the OS key store, as far as the probe needs it.
type Keyring interface {
	Set(key, value string) error
	Get(key string) (string, error)
	Delete(key string) error
}

// Options configure a run. Zero values use the real system.
type Options struct {
	// GPGPath is "", "auto" or a path.
	GPGPath string
	// NeedGPG marks gpg and everything behind it as required (a GPG layer is
	// enabled). Otherwise their failures are warnings: not needed yet.
	NeedGPG bool
	// Keyring is probed with a throw-away entry; nil skips the check.
	Keyring Keyring
	// SpoolDir is where temporary files go; "" means os.TempDir().
	SpoolDir string

	LookPath func(string) (string, error)
	Run      seclayer.Runner
}

// Check runs every check. It never writes outside throw-away entries and
// temporary files, and removes those.
func Check(ctx context.Context, o Options) Report {
	if o.LookPath == nil {
		o.LookPath = exec.LookPath
	}
	if o.Run == nil {
		o.Run = seclayer.ExecRunner
	}
	var items []Item

	g, gerr := seclayer.LocateWith(ctx, o.GPGPath, o.LookPath, o.Run)
	items = append(items, gpgItem(g, gerr, o))

	if gerr == nil {
		items = append(items, selfTestItem(ctx, g, o), agentItem(ctx, o))
	} else {
		items = append(items,
			skipped(IDGPGTest, "gpg round trip", o.NeedGPG, "needs gpg"),
			skipped(IDAgent, "gpg-agent", o.NeedGPG, "needs gpg"))
	}
	if o.Keyring != nil {
		items = append(items, keyringItem(o))
	}
	items = append(items, spoolItem(o))

	ready := true
	for _, it := range items {
		if it.Required && it.Status == Fail {
			ready = false
		}
	}
	return Report{Items: items, Ready: ready}
}

func skipped(id, name string, required bool, why string) Item {
	st := Warn
	if required {
		st = Fail
	}
	return Item{ID: id, Name: name, Required: required, Status: st, Detail: "not checked: " + why}
}

// failStatus is Fail for required components, Warn for optional ones.
func failStatus(required bool) Status {
	if required {
		return Fail
	}
	return Warn
}

func gpgItem(g *seclayer.GPG, err error, o Options) Item {
	it := Item{ID: IDGPG, Name: "GnuPG (gpg)", Required: o.NeedGPG}
	switch {
	case err == nil:
		it.Status, it.Path, it.Version = OK, g.Exe, g.Version
		it.Detail = fmt.Sprintf("found %s", g.Version)
	case g != nil && g.Exe != "":
		it.Status, it.Path, it.Version = failStatus(o.NeedGPG), g.Exe, g.Version
		it.Detail = err.Error()
		it.Hint = installHint()
	default:
		it.Status = failStatus(o.NeedGPG)
		it.Detail = err.Error()
		it.Hint = installHint()
	}
	if it.Status == Warn {
		it.Detail += " (only needed once a GPG layer is enabled)"
	}
	return it
}

func installHint() string {
	return "Install GnuPG 2.2 or newer: apt install gnupg, brew install gnupg, or Gpg4win on Windows; " +
		"or set the gpg path explicitly. The gpg inside Git for Windows or MSYS2 is not supported."
}

func selfTestItem(ctx context.Context, g *seclayer.GPG, o Options) Item {
	it := Item{ID: IDGPGTest, Name: "gpg encrypt/decrypt round trip", Required: o.NeedGPG}
	cctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	key, err := seclayer.GenerateKey()
	if err != nil {
		it.Status, it.Detail = Fail, err.Error()
		return it
	}
	gg := seclayer.New(g.Exe, o.Run)
	const probe = "securePail readiness probe"
	ct, err := gg.EncryptBytes(cctx, []byte(probe), key, false)
	if err == nil {
		var pt []byte
		pt, err = gg.DecryptBytes(cctx, ct, key, 1<<16)
		if err == nil && string(pt) != probe {
			err = fmt.Errorf("round trip returned different data")
		}
	}
	if err != nil {
		it.Status = failStatus(o.NeedGPG)
		it.Detail = "gpg is installed but cannot encrypt non-interactively: " + err.Error()
		it.Hint = "Check that gpg-agent.conf does not disable loopback pinentry (remove \"no-allow-loopback-pinentry\"), " +
			"then run: gpgconf --kill gpg-agent"
		return it
	}
	it.Status, it.Detail = OK, "encrypted and decrypted a test message with integrity protection"
	return it
}

func agentItem(ctx context.Context, o Options) Item {
	it := Item{ID: IDAgent, Name: "gpg-agent", Required: false}
	exe, err := o.LookPath("gpgconf")
	if err != nil {
		it.Status = Warn
		it.Detail = "gpgconf not found; gpg starts its agent on demand"
		return it
	}
	cctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	var sb strings.Builder
	if _, err := o.Run(cctx, exe, []string{"--list-dirs", "agent-socket"}, nil, &sb); err != nil {
		it.Status, it.Path, it.Detail = Warn, exe, "gpgconf could not locate the agent socket: "+err.Error()
		return it
	}
	sock := strings.TrimSpace(sb.String())
	it.Status, it.Path = OK, exe
	it.Detail = "agent socket: " + sock
	if len(sock) > 100 {
		it.Status = Warn
		it.Detail = "agent socket path is long and may exceed the system limit: " + sock
		it.Hint = "Set GNUPGHOME to a shorter directory."
	}
	return it
}

func keyringItem(o Options) Item {
	it := Item{ID: IDKeyring, Name: "OS key store", Required: true}
	const k, v = "securepail-readiness-probe", "probe"
	if err := o.Keyring.Set(k, v); err != nil {
		it.Status, it.Detail = Fail, "cannot store a secret: "+err.Error()
		it.Hint = "Secure-layer keys live in the OS key store (Keychain, Credential Manager, Secret Service). " +
			"On Linux install and unlock gnome-keyring or KWallet; on a server or other machine without a desktop, " +
			"use the encrypted vault instead: pail vault init, then pail vault backend vault."
		return it
	}
	got, err := o.Keyring.Get(k)
	_ = o.Keyring.Delete(k)
	if err != nil || got != v {
		it.Status, it.Detail = Fail, "stored a secret but could not read it back"
		return it
	}
	it.Status, it.Detail = OK, "stored, read back and removed a test secret"
	return it
}

func spoolItem(o Options) Item {
	dir := o.SpoolDir
	if dir == "" {
		dir = os.TempDir()
	}
	it := Item{ID: IDSpoolDir, Name: "Temporary directory", Required: true, Path: dir}
	f, err := os.CreateTemp(dir, "securepail-ready-*")
	if err != nil {
		it.Status, it.Detail = Fail, "not writable: "+err.Error()
		it.Hint = "Encrypted uploads are staged as a temporary file the size of the original. Set TMPDIR to a writable disk."
		return it
	}
	name := f.Name()
	f.Close()
	os.Remove(name)
	it.Status, it.Detail = OK, "writable"
	return it
}

// Render formats a report for a terminal.
func (r Report) Render() string {
	var b strings.Builder
	for _, it := range r.Items {
		mark := map[Status]string{OK: "[ok]  ", Warn: "[warn]", Fail: "[FAIL]"}[it.Status]
		fmt.Fprintf(&b, "%s %s: %s\n", mark, it.Name, it.Detail)
		if it.Path != "" {
			fmt.Fprintf(&b, "         path: %s\n", it.Path)
		}
		if it.Hint != "" && it.Status != OK {
			fmt.Fprintf(&b, "         fix:  %s\n", it.Hint)
		}
	}
	if r.Ready {
		b.WriteString("Ready.\n")
	} else {
		b.WriteString("Not ready: fix the failures above.\n")
	}
	return b.String()
}
