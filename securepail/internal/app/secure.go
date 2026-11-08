package app

// The client-side secure layer. An upload rule with a GPG layer encrypts each
// file with gpg before it leaves the computer; the object gets the suffix
// ".gpg" and the marker pail-secure=gpg. Downloads in auto mode undo it.
//
// The key is a secret in the key store (see secrets.go), referenced by name:
// either a generated vault key (fast) or a human passphrase (slow, strong
// S2K). Keys are never written to rules, logs or object metadata. Losing the
// key loses the data, so ExportSecureKey makes a password-protected backup
// that plain `gpg -d` can open.

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/jstdlee/securePail/internal/readiness"
	"github.com/jstdlee/securePail/internal/rules"
	"github.com/jstdlee/securePail/internal/seclayer"
)

const (
	// secureMetaKey marks objects encrypted by the secure layer; the value is the suite ID ("aesgcm" or "gpg").
	secureMetaKey = "pail-secure"
)

// ErrSecureKeyMissing is wrapped when an encrypted object is downloaded
// without naming the key.
var errSecureKeyRequired = errors.New("the object is encrypted by the GPG layer; name the key with a key reference")

// locateGPG finds gpg; tests replace it.
var locateGPG = func(ctx context.Context) (*seclayer.GPG, error) {
	path := os.Getenv("SECUREPAIL_GPG")
	return seclayer.Locate(ctx, path)
}

// secureGPG returns a usable gpg or an error that says how to fix it.
func (s *Service) secureGPG(ctx context.Context, op string) (*seclayer.GPG, error) {
	g, err := locateGPG(ctx)
	if err != nil {
		return nil, opErr(op, ErrInvalid, "the GPG layer needs gpg: %v (run the readiness check: pail doctor)", err)
	}
	return g, nil
}

// secureKey resolves a key reference to the secret.
func (s *Service) secureKey(ctx context.Context, ref string) (string, error) {
	return s.secretValue(ctx, ref)
}

// secureCtx is a validated secure layer, ready to use.
type secureCtx struct {
	suite seclayer.Suite
	gpg   *seclayer.GPG // only for the gpg suite
	key   string
}

// suffix is what the layer adds to the object key.
func secureSuffixFor(method string) string {
	if st, ok := seclayer.SuiteByID(method); ok {
		return st.Suffix
	}
	return ""
}

// spoolEncrypted encrypts the file at srcPath into a new temporary file
// (rewound) and returns it with its size. The caller deletes it.
func (s *Service) spoolEncrypted(ctx context.Context, sc *secureCtx, srcPath string, compress bool) (*os.File, int64, error) {
	tmp, err := os.CreateTemp("", spoolPrefix+"*"+spoolSuffix)
	if err != nil {
		return nil, 0, err
	}
	ok := false
	defer func() {
		if !ok {
			tmp.Close()
			os.Remove(tmp.Name())
		}
	}()
	switch sc.suite.ID {
	case seclayer.SuiteGPG:
		err = sc.gpg.Encrypt(ctx, srcPath, tmp, sc.key, seclayer.StrongS2K(sc.key), compress)
	case seclayer.SuiteAESGCM:
		var in *os.File
		if in, err = os.Open(srcPath); err == nil {
			err = seclayer.EncryptStream(tmp, ctxReader{ctx, in}, sc.key)
			in.Close()
		}
	default:
		err = fmt.Errorf("unsupported secure layer %q", sc.suite.ID)
	}
	if err != nil {
		return nil, 0, err
	}
	fi, err := tmp.Stat()
	if err != nil {
		return nil, 0, err
	}
	if _, err := tmp.Seek(0, io.SeekStart); err != nil {
		return nil, 0, err
	}
	ok = true
	return tmp, fi.Size(), nil
}

// ctxReader stops a long read when the task is cancelled.
type ctxReader struct {
	ctx context.Context
	r   io.Reader
}

func (c ctxReader) Read(p []byte) (int, error) {
	if err := c.ctx.Err(); err != nil {
		return 0, err
	}
	return c.r.Read(p)
}

// decryptInto decrypts the downloaded file in into out with the suite named
// by the object's marker, enforcing the size limit. Nothing is published here.
func (s *Service) decryptInto(ctx context.Context, in, out *os.File, method, keyRef string, limit int64) error {
	const op = "Download"
	if keyRef == "" {
		return invalid(op, "%v", errSecureKeyRequired)
	}
	suite, ok := seclayer.SuiteByID(strings.ToLower(method))
	if !ok {
		return opErr(op, ErrInvalid, "the object uses an unknown secure layer %q; update securePail", method)
	}
	key, err := s.secureKey(ctx, keyRef)
	if err != nil {
		return err
	}
	var w io.Writer = out
	lw := &capWriter{w: out, left: limit}
	if limit > 0 {
		w = lw
	}
	switch suite.ID {
	case seclayer.SuiteGPG:
		g, gerr := s.secureGPG(ctx, op)
		if gerr != nil {
			return gerr
		}
		err = g.Decrypt(ctx, in.Name(), w, key)
	default:
		if _, serr := in.Seek(0, io.SeekStart); serr != nil {
			return classify(op, serr)
		}
		err = seclayer.DecryptStream(w, ctxReader{ctx, in}, key)
	}
	if err != nil {
		if lw.hit {
			return opErr(op, ErrInvalid, "the decrypted content exceeds the size limit")
		}
		switch {
		case errors.Is(err, seclayer.ErrBadPassphrase):
			return opErr(op, ErrInvalid, "wrong key for this object; nothing was saved")
		case errors.Is(err, seclayer.ErrTampered):
			return opErr(op, ErrInvalid, "wrong key, or the object is damaged or was modified; nothing was saved")
		case errors.Is(err, seclayer.ErrNotEncrypted):
			return opErr(op, ErrInvalid, "the object is not an encrypted file of the %s suite; nothing was saved", suite.Name)
		}
		return classify(op, err)
	}
	return nil
}

type capWriter struct {
	w    io.Writer
	left int64
	hit  bool
}

func (c *capWriter) Write(p []byte) (int, error) {
	if int64(len(p)) > c.left {
		c.hit = true
		return 0, errors.New("size limit")
	}
	c.left -= int64(len(p))
	return c.w.Write(p)
}

// secure reports whether the object says a secure layer was applied.
func (h decodeHints) secure() bool { return h.Secure != "" }

// validateSecureOpts checks a matched secure layer before any work starts.
func (s *Service) validateSecureOpts(ctx context.Context, op string, sec *rules.Secure) (*secureCtx, error) {
	if sec == nil {
		return nil, nil
	}
	suite, ok := seclayer.SuiteByID(sec.Method)
	if !ok {
		return nil, invalid(op, "unsupported secure layer %q", sec.Method)
	}
	sc := &secureCtx{suite: suite}
	if suite.NeedsGPG {
		g, err := s.secureGPG(ctx, op)
		if err != nil {
			return nil, err
		}
		sc.gpg = g
	}
	key, err := s.secureKey(ctx, sec.KeyRef)
	if err != nil {
		return nil, err
	}
	if !suite.PassphraseKeys && !seclayer.IsGeneratedKey(key) {
		return nil, invalid(op, "the %s layer needs a generated key, and %q is a typed passphrase; create one with: pail secure keygen NAME", suite.Name, sec.KeyRef)
	}
	sc.key = key
	return sc, nil
}

// GenerateSecureKey creates a random vault key and stores it under ref. It
// refuses to replace an existing secret: an overwritten key makes every
// object encrypted with it unreadable.
func (s *Service) GenerateSecureKey(ref string) error {
	const op = "SecureKey"
	for _, r := range s.SecretRefs() {
		if r == ref {
			return invalid(op, "a secret named %q already exists; choose another name", ref)
		}
	}
	key, err := seclayer.GenerateKey()
	if err != nil {
		return classify(op, err)
	}
	return s.SetSecret(ref, key)
}

// SetSecurePassphrase stores a human passphrase as a key, after a strength check.
func (s *Service) SetSecurePassphrase(ref, passphrase string) error {
	const op = "SecureKey"
	if st := seclayer.CheckPassword(passphrase); !st.Acceptable {
		return invalid(op, "the passphrase is too weak: %s", strings.Join(st.Problems, "; "))
	}
	for _, r := range s.SecretRefs() {
		if r == ref {
			return invalid(op, "a secret named %q already exists; choose another name", ref)
		}
	}
	return s.SetSecret(ref, passphrase)
}

// SecureKeyFormat selects the backup file format.
type SecureKeyFormat string

// Backup formats.
const (
	// KeyFileJSON is the portable key file (PBKDF2 + AES-GCM): needs no tools
	// and opens on every platform. Only for generated keys.
	KeyFileJSON SecureKeyFormat = "keyfile"
	// KeyFileGPG is the key wrapped by gpg; open it with `gpg -d`.
	KeyFileGPG SecureKeyFormat = "gpg"
)

// ExportSecureKey returns the key under ref protected with password.
func (s *Service) ExportSecureKey(ctx context.Context, ref, password string, format SecureKeyFormat) ([]byte, error) {
	const op = "SecureKey"
	if st := seclayer.CheckPassword(password); !st.Acceptable {
		return nil, invalid(op, "the backup password is too weak: %s", strings.Join(st.Problems, "; "))
	}
	key, err := s.secureKey(ctx, ref)
	if err != nil {
		return nil, err
	}
	switch format {
	case "", KeyFileJSON:
		b, err := seclayer.MakeKeyFile(key, password, seclayer.DefaultPBKDF2)
		if err != nil {
			return nil, invalid(op, "%v (use --format gpg for a typed passphrase)", err)
		}
		return b, nil
	case KeyFileGPG:
		g, err := s.secureGPG(ctx, op)
		if err != nil {
			return nil, err
		}
		b, err := g.WrapKey(ctx, key, password)
		if err != nil {
			return nil, classify(op, err)
		}
		return b, nil
	}
	return nil, invalid(op, "unknown key file format %q", format)
}

// SecureRecoveryKey shows a generated key as 16 groups of hex digits.
func (s *Service) SecureRecoveryKey(ctx context.Context, ref string) (string, error) {
	key, err := s.secureKey(ctx, ref)
	if err != nil {
		return "", err
	}
	r, err := seclayer.RecoveryString(key)
	if err != nil {
		return "", invalid("SecureKey", "%v", err)
	}
	return r, nil
}

// ImportSecureKey restores a key from a key file (either format, detected) or
// a recovery key (password ignored) under a new ref.
func (s *Service) ImportSecureKey(ctx context.Context, ref string, data []byte, password string) error {
	const op = "SecureKey"
	for _, r := range s.SecretRefs() {
		if r == ref {
			return invalid(op, "a secret named %q already exists; choose another name", ref)
		}
	}
	var key string
	var err error
	switch {
	case seclayer.IsKeyFile(data):
		key, err = seclayer.OpenKeyFile(data, password)
	case bytes.HasPrefix(bytes.TrimSpace(data), []byte("-----")) || len(data) > 0 && data[0]&0x80 != 0:
		var g *seclayer.GPG
		if g, err = s.secureGPG(ctx, op); err != nil {
			return err
		}
		key, err = g.UnwrapKey(ctx, data, password)
	default:
		if key, err = seclayer.ParseRecovery(string(data)); err != nil {
			return invalid(op, "this is neither a key file nor a recovery key")
		}
	}
	if err != nil {
		if errors.Is(err, seclayer.ErrBadPassphrase) {
			return invalid(op, "wrong password for the key file")
		}
		return invalid(op, "%v", err)
	}
	return s.SetSecret(ref, key)
}

// Readiness checks the components the secure layer needs. gpg counts as
// required when any enabled upload rule uses the GPG suite.
func (s *Service) Readiness(ctx context.Context) readiness.Report {
	return s.ReadinessFor(ctx, false)
}

// ReadinessFor is Readiness with an option to require gpg even when no rule
// uses it yet (a pre-flight check before enabling a layer).
func (s *Service) ReadinessFor(ctx context.Context, requireGPG bool) readiness.Report {
	need := requireGPG
	for _, r := range s.UploadRules() {
		if !r.Disabled && r.Secure != nil && r.Secure.Method == seclayer.SuiteGPG {
			need = true
		}
	}
	return readiness.Check(ctx, readiness.Options{
		GPGPath: os.Getenv("SECUREPAIL_GPG"),
		NeedGPG: need,
		Keyring: s.kr,
	})
}

// seclayerCompressed reports whether gpg should skip its own compression for a file.
func seclayerCompressed(local string) bool {
	return seclayer.IsCompressedExt(local)
}
