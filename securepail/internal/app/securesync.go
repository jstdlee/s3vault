package app

// Secure sync: two-way synchronisation of a local folder with a bucket prefix,
// with optional client-side encryption per root (see secure.go), a remote
// trash, device registry and conflict handling. It is the vault side of
// securePail, modelled on s3vault, and is independent of the one-way sync jobs
// in sync.go.
//
// Remote layout below the root's prefix:
//
//	.securepail/vault.json          marker (format, id; no secrets)
//	.securepail/devices/<id>.json   one file per device that synced
//	.securepail/trash/<ts>/<key>    soft-deleted objects, purged after TrashDays
//	<path>                          plain file
//	<path>.spe | <path>.gpg         encrypted file (the suite's suffix)
//
// The remote version of a file is its ETag; the local version is the SHA-256 of
// the plaintext. The base (vsync.Index) records both after each successful
// sync of a path, and vsync.Decide turns local, remote and base into one
// action. Every write is conditional (If-Match / If-None-Match), so a device
// that loses a race re-plans the path instead of overwriting a newer version.

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"os"
	"path"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/jstdlee/securePail/internal/seclayer"
)

const (
	secureRootsFile = "secure-roots.json"
	deviceFile      = "device.json"
	secureMetaDir   = ".securepail/"
	secureTrashDir  = secureMetaDir + "trash/"
	secureDevDir    = secureMetaDir + "devices/"
	secureMarker    = secureMetaDir + "vault.json"

	defaultTrashDays = 30
	// maxCheckBytes bounds the fetch that tells "same content" from "conflict"
	// when both sides changed; above it the path is a conflict without the check.
	maxCheckBytes = 256 << 20
)

// SecureRoot is one synchronised folder.
type SecureRoot struct {
	ID        string `json:"id"`
	Name      string `json:"name"`
	AccountID string `json:"accountId"`
	Bucket    string `json:"bucket"`
	// Prefix is the folder inside the bucket; "" or ending in "/".
	Prefix string `json:"prefix"`
	// Local is the absolute path of the local folder.
	Local string `json:"local"`
	// Method is the encryption suite ("aesgcm", "gpg") or "" for plain files.
	Method string `json:"method,omitempty"`
	// KeyRef names the key in the key store (required with Method).
	KeyRef string `json:"keyRef,omitempty"`
	// PlainGlobs match files that are stored unencrypted even with a Method.
	PlainGlobs []string `json:"plainGlobs,omitempty"`
	// Excludes match files that are never synchronised.
	Excludes []string `json:"excludes,omitempty"`
	// TrashDays: how long remote deletions are kept; 0 means 30.
	TrashDays int `json:"trashDays,omitempty"`
}

// Device identifies this installation in conflict names and the registry.
type Device struct {
	ID   string `json:"id"`
	Name string `json:"name"`
}

// secureState is the loaded list of roots, guarded by its own mutex.
type secureState struct {
	mu    sync.Mutex
	roots []SecureRoot
	loadd bool
	dev   Device
	// per-root run lock: one sync of a root at a time
	running map[string]bool
	edits   map[string]*editSession
}

func (s *Service) loadSecure() error {
	st := &s.sec
	st.mu.Lock()
	defer st.mu.Unlock()
	if st.loadd {
		return nil
	}
	if _, err := readJSON(s.path(secureRootsFile), &st.roots); err != nil {
		return err
	}
	if found, err := readJSON(s.path(deviceFile), &st.dev); err != nil {
		return err
	} else if !found || st.dev.ID == "" {
		var b [4]byte
		_, _ = rand.Read(b[:])
		host, _ := os.Hostname()
		if host == "" {
			host = "device"
		}
		st.dev = Device{ID: hex.EncodeToString(b[:]), Name: host}
		if err := writeJSONAtomic(s.path(deviceFile), st.dev); err != nil {
			return err
		}
	}
	st.running, st.edits, st.loadd = map[string]bool{}, map[string]*editSession{}, true
	return nil
}

// SecureDevice returns this installation's device identity.
func (s *Service) SecureDevice() (Device, error) {
	if err := s.loadSecure(); err != nil {
		return Device{}, classify("SecureDevice", err)
	}
	s.sec.mu.Lock()
	defer s.sec.mu.Unlock()
	return s.sec.dev, nil
}

// SecureRoots returns the saved roots.
func (s *Service) SecureRoots() ([]SecureRoot, error) {
	if err := s.loadSecure(); err != nil {
		return nil, classify("SecureRoots", err)
	}
	s.sec.mu.Lock()
	defer s.sec.mu.Unlock()
	return append([]SecureRoot(nil), s.sec.roots...), nil
}

func (s *Service) secureRoot(op, id string) (SecureRoot, error) {
	roots, err := s.SecureRoots()
	if err != nil {
		return SecureRoot{}, err
	}
	for _, r := range roots {
		if r.ID == id || (r.Name != "" && r.Name == id) {
			return r, nil
		}
	}
	return SecureRoot{}, opErr(op, ErrNotFound, "no secure root %q", id)
}

func normalizeRoot(op string, r SecureRoot) (SecureRoot, error) {
	r.Name = strings.TrimSpace(r.Name)
	if r.Name == "" {
		return r, invalid(op, "a root needs a name")
	}
	if r.AccountID == "" || r.Bucket == "" {
		return r, invalid(op, "a root needs an account and a bucket")
	}
	if r.Prefix != "" {
		r.Prefix = strings.Trim(r.Prefix, "/") + "/"
		if r.Prefix == "/" {
			r.Prefix = ""
		}
	}
	if !filepath.IsAbs(r.Local) {
		return r, invalid(op, "the local folder must be an absolute path")
	}
	r.Local = filepath.Clean(r.Local)
	if r.Method != "" {
		if _, ok := seclayer.SuiteByID(r.Method); !ok {
			return r, invalid(op, "unknown encryption suite %q", r.Method)
		}
		if err := validRefName(r.KeyRef); err != nil {
			return r, invalid(op, "encryption needs a key reference: %v", err)
		}
	}
	if r.TrashDays < 0 || r.TrashDays > 3650 {
		return r, invalid(op, "trash days must be between 0 and 3650")
	}
	return r, nil
}

// SaveSecureRoot creates (empty ID) or replaces a root. Changing Method or
// KeyRef of a populated root does not re-encrypt: new and changed files use the
// new settings and existing remote files stay as they are.
func (s *Service) SaveSecureRoot(r SecureRoot) (SecureRoot, error) {
	const op = "SaveSecureRoot"
	r, err := normalizeRoot(op, r)
	if err != nil {
		return SecureRoot{}, err
	}
	if err := s.loadSecure(); err != nil {
		return SecureRoot{}, classify(op, err)
	}
	st := &s.sec
	st.mu.Lock()
	defer st.mu.Unlock()
	next := append([]SecureRoot(nil), st.roots...)
	if r.ID == "" {
		for i := 0; i < 100 && r.ID == ""; i++ {
			var b [6]byte
			_, _ = rand.Read(b[:])
			r.ID = "root-" + hex.EncodeToString(b[:])
		}
		next = append(next, r)
	} else {
		found := false
		for i := range next {
			if next[i].ID == r.ID {
				next[i], found = r, true
			}
		}
		if !found {
			return SecureRoot{}, opErr(op, ErrNotFound, "no secure root %q", r.ID)
		}
	}
	names := map[string]bool{}
	for _, x := range next {
		if names[x.Name] {
			return SecureRoot{}, invalid(op, "a root named %q already exists", x.Name)
		}
		names[x.Name] = true
	}
	if err := writeJSONAtomic(s.path(secureRootsFile), next); err != nil {
		return SecureRoot{}, classify(op, err)
	}
	st.roots = next
	return r, nil
}

// DeleteSecureRoot forgets a root and its base index. Local and remote files
// are not touched.
func (s *Service) DeleteSecureRoot(id string) error {
	const op = "DeleteSecureRoot"
	root, err := s.secureRoot(op, id)
	if err != nil {
		return err
	}
	st := &s.sec
	st.mu.Lock()
	defer st.mu.Unlock()
	var next []SecureRoot
	for _, x := range st.roots {
		if x.ID != root.ID {
			next = append(next, x)
		}
	}
	if err := writeJSONAtomic(s.path(secureRootsFile), next); err != nil {
		return classify(op, err)
	}
	st.roots = next
	_ = os.Remove(s.indexPath(root))
	return nil
}

func (s *Service) indexPath(r SecureRoot) string {
	return s.path("secure-index-" + r.ID + ".json")
}

// ---- remote key mapping ---------------------------------------------------

// encrypted reports whether the file at rel is stored encrypted under r.
func (r SecureRoot) encrypted(rel string) bool {
	if r.Method == "" {
		return false
	}
	for _, g := range r.PlainGlobs {
		if matchGlob(g, rel) {
			return false
		}
	}
	return true
}

func (r SecureRoot) suffix() string { return secureSuffixFor(r.Method) }

// remoteKey is the object key for rel.
func (r SecureRoot) remoteKey(rel string) string {
	k := r.Prefix + rel
	if r.encrypted(rel) {
		k += r.suffix()
	}
	return k
}

// logicalPath maps an object key to (rel, encryptedObject, ok). Keys outside
// the prefix, in the meta folder or folder placeholders are not files.
func (r SecureRoot) logicalPath(key string) (string, bool, bool) {
	if !strings.HasPrefix(key, r.Prefix) || strings.HasSuffix(key, "/") {
		return "", false, false
	}
	rel := strings.TrimPrefix(key, r.Prefix)
	if strings.HasPrefix(rel, secureMetaDir) || rel == "" {
		return "", false, false
	}
	if r.Method != "" {
		if sfx := r.suffix(); strings.HasSuffix(rel, sfx) && len(rel) > len(sfx) {
			return strings.TrimSuffix(rel, sfx), true, true
		}
	}
	return rel, false, true
}

func (r SecureRoot) excluded(rel string) bool {
	for _, g := range r.Excludes {
		if matchGlob(g, rel) || matchGlob(g, path.Base(rel)) {
			return true
		}
	}
	return false
}

func (r SecureRoot) trashDays() int {
	if r.TrashDays > 0 {
		return r.TrashDays
	}
	return defaultTrashDays
}

func matchGlob(pattern, name string) bool {
	if ok, _ := path.Match(pattern, name); ok {
		return true
	}
	// "dir/**" style: match any path below dir.
	if strings.HasSuffix(pattern, "/**") {
		return strings.HasPrefix(name, strings.TrimSuffix(pattern, "**"))
	}
	return false
}

func sortedKeys[V any](m map[string]V) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// vaultMarker is the content of .securepail/vault.json.
type vaultMarker struct {
	Format  string    `json:"format"`
	Version int       `json:"version"`
	Created time.Time `json:"created"`
	Suite   string    `json:"suite,omitempty"`
}

func marshalMarker(r SecureRoot) []byte {
	b, _ := json.MarshalIndent(vaultMarker{Format: "securepail-vault", Version: 1,
		Created: time.Now().UTC().Truncate(time.Second), Suite: r.Method}, "", "  ")
	return b
}
