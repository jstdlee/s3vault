// Package seclayer is the client-side secure layer: OpenPGP symmetric
// encryption through the gpg command-line tool.
//
// The format is plain OpenPGP (SKESK + SEIPD, AES-256), so objects can be
// recovered with gpg alone. The passphrase travels only on gpg's standard
// input (--passphrase-fd 0); the data goes in as a file argument and out on
// standard output, so no platform-specific inherited handles are needed and
// the passphrase never appears in argv, the environment or a file.
package seclayer

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"regexp"
	"strconv"
	"strings"
	"time"
)

// Status classifies the outcome of one gpg run.
type Status int

// Outcomes of an encrypt or decrypt run.
const (
	StatusOK Status = iota
	StatusBadPassphrase
	StatusNotEncrypted
	StatusTampered
	StatusFailed
)

// Error is returned for every failed gpg run.
type Error struct {
	Status Status
	Detail string
}

func (e *Error) Error() string { return e.Detail }

// Is lets callers match the sentinel errors below.
func (e *Error) Is(target error) bool {
	t, ok := target.(*Error)
	return ok && t.Status == e.Status
}

// Sentinels for errors.Is.
var (
	ErrBadPassphrase = &Error{Status: StatusBadPassphrase}
	ErrNotEncrypted  = &Error{Status: StatusNotEncrypted}
	ErrTampered      = &Error{Status: StatusTampered}
	ErrNoGPG         = errors.New("gpg was not found")
)

// MinMajor and MinMinor are the oldest supported gpg.
const (
	MinMajor = 2
	MinMinor = 2
)

// Runner starts a process; tests replace it.
type Runner func(ctx context.Context, name string, args []string, stdin io.Reader, stdout io.Writer) (stderr string, err error)

// ExecRunner runs a real process.
func ExecRunner(ctx context.Context, name string, args []string, stdin io.Reader, stdout io.Writer) (string, error) {
	cmd := exec.CommandContext(ctx, name, args...)
	cmd.Stdin = stdin
	cmd.Stdout = stdout
	var eb bytes.Buffer
	cmd.Stderr = &eb
	err := cmd.Run()
	return eb.String(), err
}

// GPG is a located gpg executable.
type GPG struct {
	Exe     string
	Version string
	run     Runner
}

var versionRE = regexp.MustCompile(`(\d+)\.(\d+)(?:\.(\d+))?`)

// ParseVersion extracts "major.minor.patch" from `gpg --version` output.
func ParseVersion(out string) (version string, major, minor int, ok bool) {
	first := strings.TrimSpace(strings.SplitN(out, "\n", 2)[0])
	m := versionRE.FindStringSubmatch(first)
	if m == nil {
		return "", 0, 0, false
	}
	major, _ = strconv.Atoi(m[1])
	minor, _ = strconv.Atoi(m[2])
	return m[0], major, minor, true
}

// VersionOK reports whether a version satisfies the minimum.
func VersionOK(major, minor int) bool {
	return major > MinMajor || (major == MinMajor && minor >= MinMinor)
}

// Locate finds gpg. configured is "", "auto" or a path/name; with auto, gpg
// and gpg2 are tried. The returned GPG is usable only when err is nil.
func Locate(ctx context.Context, configured string) (*GPG, error) {
	return LocateWith(ctx, configured, exec.LookPath, ExecRunner)
}

// LocateWith is Locate with injectable lookup and runner.
func LocateWith(ctx context.Context, configured string, look func(string) (string, error), run Runner) (*GPG, error) {
	names := []string{configured}
	if configured == "" || configured == "auto" {
		names = []string{"gpg", "gpg2"}
	}
	var exe string
	for _, n := range names {
		if p, err := look(n); err == nil {
			exe = p
			break
		}
	}
	if exe == "" {
		return nil, ErrNoGPG
	}
	cctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	var out bytes.Buffer
	if _, err := run(cctx, exe, []string{"--version"}, nil, &out); err != nil {
		return nil, fmt.Errorf("%s --version failed: %w", exe, err)
	}
	v, maj, min, ok := ParseVersion(out.String())
	if !ok {
		return &GPG{Exe: exe}, fmt.Errorf("cannot read the version of %s", exe)
	}
	g := &GPG{Exe: exe, Version: v, run: run}
	if !VersionOK(maj, min) {
		return g, fmt.Errorf("gpg %s is too old (need %d.%d or newer)", v, MinMajor, MinMinor)
	}
	return g, nil
}

// New wraps a known executable (tests, or after Locate).
func New(exe string, run Runner) *GPG {
	if run == nil {
		run = ExecRunner
	}
	return &GPG{Exe: exe, run: run}
}

// Strong S2K (iterated and salted, maximum count) is for human passphrases;
// salted S2K is for high-entropy generated keys, where iteration only costs time.
const strongS2KCount = "65011712"

func (g *GPG) encryptArgs(strong bool, compress bool, inPath string) []string {
	a := []string{"--batch", "--quiet", "--no-tty", "--no-greeting", "--no-symkey-cache",
		"--pinentry-mode", "loopback", "--passphrase-fd", "0", "--status-fd", "2",
		"--symmetric", "--cipher-algo", "AES256", "--s2k-digest-algo", "SHA512", "--set-filename", ""}
	if strong {
		a = append(a, "--s2k-mode", "3", "--s2k-count", strongS2KCount)
	} else {
		a = append(a, "--s2k-mode", "1")
	}
	if !compress {
		a = append(a, "--compress-algo", "none")
	}
	return append(a, "-o", "-", "--", inPath)
}

func (g *GPG) decryptArgs(inPath string) []string {
	return []string{"--batch", "--quiet", "--no-tty", "--no-greeting", "--no-symkey-cache",
		"--pinentry-mode", "loopback", "--passphrase-fd", "0", "--status-fd", "2",
		"--decrypt", "-o", "-", "--", inPath}
}

// Encrypt encrypts the file at inPath into out. strong selects the slow
// iterated S2K for human passphrases. compress lets gpg compress first; leave
// it off for data that is already compressed.
func (g *GPG) Encrypt(ctx context.Context, inPath string, out io.Writer, pass string, strong, compress bool) error {
	if g == nil || g.Exe == "" {
		return ErrNoGPG
	}
	if pass == "" {
		return &Error{Status: StatusFailed, Detail: "empty passphrase"}
	}
	stderr, err := g.run(ctx, g.Exe, g.encryptArgs(strong, compress, inPath), strings.NewReader(pass+"\n"), out)
	if cerr := ctx.Err(); cerr != nil {
		return cerr
	}
	return Classify(err, stderr)
}

// Decrypt decrypts the file at inPath into out. Anything that was not
// decrypted with integrity protection is refused, so a plain OpenPGP literal
// packet planted in place of the ciphertext does not "decrypt".
func (g *GPG) Decrypt(ctx context.Context, inPath string, out io.Writer, pass string) error {
	if g == nil || g.Exe == "" {
		return ErrNoGPG
	}
	stderr, err := g.run(ctx, g.Exe, g.decryptArgs(inPath), strings.NewReader(pass+"\n"), out)
	if cerr := ctx.Err(); cerr != nil {
		return cerr
	}
	if cerr := Classify(err, stderr); cerr != nil {
		return cerr
	}
	return CheckIntegrity(stderr)
}

// Classify maps gpg's exit state and --status-fd output to an *Error (nil on success).
func Classify(runErr error, status string) error {
	has := func(s string) bool { return strings.Contains(status, s) }
	switch {
	case has("BAD_PASSPHRASE") || has("Bad session key"):
		return &Error{StatusBadPassphrase, "wrong password or key"}
	case has("[GNUPG:] DECRYPTION_FAILED") || has("BADMDC") || has("manipulated"):
		return &Error{StatusTampered, "decryption failed (damaged or modified data)"}
	case runErr != nil:
		msg := ""
		for _, l := range strings.Split(status, "\n") {
			l = strings.TrimSpace(l)
			if l != "" && !strings.HasPrefix(l, "[GNUPG:]") {
				msg = l
			}
		}
		if msg == "" {
			msg = "gpg failed: " + runErr.Error()
		}
		return &Error{StatusFailed, msg}
	}
	return nil
}

// CheckIntegrity requires DECRYPTION_OKAY plus GOODMDC (SEIPDv1) or a non-zero
// AEAD algorithm in DECRYPTION_INFO.
func CheckIntegrity(status string) error {
	if !strings.Contains(status, "[GNUPG:] DECRYPTION_OKAY") {
		return &Error{StatusNotEncrypted, "object is not an encrypted OpenPGP message"}
	}
	aead := false
	if i := strings.Index(status, "[GNUPG:] DECRYPTION_INFO "); i >= 0 {
		line := status[i+len("[GNUPG:] DECRYPTION_INFO "):]
		if j := strings.IndexByte(line, '\n'); j >= 0 {
			line = line[:j]
		}
		f := strings.Fields(line)
		aead = len(f) >= 3 && f[2] != "0"
	}
	if !strings.Contains(status, "[GNUPG:] GOODMDC") && !aead {
		return &Error{StatusTampered, "message has no integrity protection"}
	}
	return nil
}

// EncryptBytes and DecryptBytes are small-data helpers (key wrapping, self-tests).
func (g *GPG) EncryptBytes(ctx context.Context, plain []byte, pass string, strong bool) ([]byte, error) {
	in, cleanup, err := tempWith(plain)
	if err != nil {
		return nil, err
	}
	defer cleanup()
	var out bytes.Buffer
	if err := g.Encrypt(ctx, in, &out, pass, strong, true); err != nil {
		return nil, err
	}
	return out.Bytes(), nil
}

// DecryptBytes is the inverse of EncryptBytes; output is capped at max bytes.
func (g *GPG) DecryptBytes(ctx context.Context, cipher []byte, pass string, max int64) ([]byte, error) {
	in, cleanup, err := tempWith(cipher)
	if err != nil {
		return nil, err
	}
	defer cleanup()
	lw := &limitWriter{max: max}
	if err := g.Decrypt(ctx, in, lw, pass); err != nil {
		return nil, err
	}
	if lw.over {
		return nil, &Error{StatusFailed, "content exceeds the size limit"}
	}
	return lw.buf.Bytes(), nil
}

type limitWriter struct {
	buf  bytes.Buffer
	max  int64
	over bool
}

func (w *limitWriter) Write(p []byte) (int, error) {
	if int64(w.buf.Len()+len(p)) > w.max {
		w.over = true
		return 0, errors.New("size limit")
	}
	return w.buf.Write(p)
}

func tempWith(b []byte) (string, func(), error) {
	f, err := os.CreateTemp("", "securepail-gpg-*")
	if err != nil {
		return "", func() {}, err
	}
	name := f.Name()
	cleanup := func() { os.Remove(name) }
	if _, err := f.Write(b); err != nil {
		f.Close()
		cleanup()
		return "", func() {}, err
	}
	if err := f.Close(); err != nil {
		cleanup()
		return "", func() {}, err
	}
	return name, cleanup, nil
}

var compressedExts = map[string]bool{}

func init() {
	for _, e := range strings.Fields("jpg jpeg png gif webp heic avif mp3 m4a aac ogg opus flac mp4 mkv mov webm avi zip gz tgz bz2 xz zst 7z rar pdf docx xlsx pptx odt epub jar apk deb rpm dmg iso") {
		compressedExts[e] = true
	}
}

// IsCompressedExt reports whether the file's extension marks data gpg should
// not try to compress again.
func IsCompressedExt(name string) bool {
	i := strings.LastIndexByte(name, '.')
	return i >= 0 && compressedExts[strings.ToLower(name[i+1:])]
}
