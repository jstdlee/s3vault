package app

// Edit sessions: open an encrypted (or plain) file from a root in a private
// temporary folder, let the user change it with any editor, and save the
// result back with a precondition on the ETag it was opened at. The temporary
// plaintext never leaves the private folder, and is overwritten and removed
// when the session ends.

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"os"
	"path"
	"path/filepath"
	"time"

	"github.com/jstdlee/securePail/internal/vsync"
)

type editSession struct {
	id, rootID, rel string
	dir, file       string
	etag            string // ETag when opened
	hash            string // plaintext hash when opened
	opened          time.Time
}

// SecureEdit describes an open edit session.
type SecureEdit struct {
	ID      string `json:"id"`
	RootID  string `json:"rootId"`
	Path    string `json:"path"`    // logical path in the root
	File    string `json:"file"`    // where to edit
	Changed bool   `json:"changed"` // the content differs from when it was opened
}

// SaveBackMode says what to do when the remote changed while editing.
type SaveBackMode string

// Save-back modes.
const (
	// SaveStrict fails with a conflict error if the remote changed.
	SaveStrict SaveBackMode = ""
	// SaveOverwrite replaces the remote version.
	SaveOverwrite SaveBackMode = "overwrite"
	// SaveKeepBoth uploads the edit under a conflict name and leaves the remote alone.
	SaveKeepBoth SaveBackMode = "keep-both"
)

func editRuntimeDir() string {
	if d := os.Getenv("XDG_RUNTIME_DIR"); d != "" {
		return filepath.Join(d, "securepail", "edit")
	}
	return filepath.Join(os.TempDir(), "securepail-edit-"+hex.EncodeToString(randBytes(4)))
}

func randBytes(n int) []byte {
	b := make([]byte, n)
	_, _ = rand.Read(b)
	return b
}

// SecureEditOpen downloads (and decrypts) rel into a private folder.
func (s *Service) SecureEditOpen(ctx context.Context, rootID, rel string) (SecureEdit, error) {
	const op = "SecureEditOpen"
	root, err := s.secureRoot(op, rootID)
	if err != nil {
		return SecureEdit{}, err
	}
	run, err := s.newSecureRun(ctx, op, root)
	if err != nil {
		return SecureEdit{}, err
	}
	ro, ok, err := run.headRemote(ctx, rel)
	if err != nil {
		return SecureEdit{}, err
	}
	if !ok {
		return SecureEdit{}, opErr(op, ErrNotFound, "%q is not in the vault", rel)
	}
	id := hex.EncodeToString(randBytes(6))
	dir := filepath.Join(editRuntimeDir(), id)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return SecureEdit{}, classify(op, err)
	}
	plain, hash, _, cleanup, err := run.fetchPlain(ctx, ro, dir)
	if err != nil {
		os.RemoveAll(dir)
		return SecureEdit{}, run.fetchErr(err)
	}
	defer cleanup()
	file := filepath.Join(dir, path.Base(rel))
	plain.Close()
	if err := os.Rename(plain.Name(), file); err != nil {
		os.RemoveAll(dir)
		return SecureEdit{}, classify(op, err)
	}
	// cleanup() would now fail to open the renamed temp: harmless (missing file).
	_ = os.Chmod(file, 0o600)
	es := &editSession{id: id, rootID: root.ID, rel: rel, dir: dir, file: file, etag: ro.etag, hash: hash, opened: time.Now()}
	s.sec.mu.Lock()
	s.sec.edits[id] = es
	s.sec.mu.Unlock()
	return SecureEdit{ID: id, RootID: root.ID, Path: rel, File: file}, nil
}

func (s *Service) editByID(op, id string) (*editSession, error) {
	if err := s.loadSecure(); err != nil {
		return nil, classify(op, err)
	}
	s.sec.mu.Lock()
	defer s.sec.mu.Unlock()
	es := s.sec.edits[id]
	if es == nil {
		return nil, opErr(op, ErrNotFound, "no open edit %q", id)
	}
	return es, nil
}

// SecureEdits lists the open sessions with their change state.
func (s *Service) SecureEdits() []SecureEdit {
	if s.loadSecure() != nil {
		return nil
	}
	s.sec.mu.Lock()
	list := make([]*editSession, 0, len(s.sec.edits))
	for _, es := range s.sec.edits {
		list = append(list, es)
	}
	s.sec.mu.Unlock()
	out := make([]SecureEdit, 0, len(list))
	for _, es := range list {
		ch, _ := es.changed()
		out = append(out, SecureEdit{ID: es.id, RootID: es.rootID, Path: es.rel, File: es.file, Changed: ch})
	}
	return out
}

func (es *editSession) changed() (bool, string) {
	h, err := hashFile(es.file)
	if err != nil {
		return false, ""
	}
	return h != es.hash, h
}

// SecureEditChanged reports whether the edit differs from what was opened.
func (s *Service) SecureEditChanged(id string) (bool, error) {
	es, err := s.editByID("SecureEditChanged", id)
	if err != nil {
		return false, err
	}
	ch, _ := es.changed()
	return ch, nil
}

// SecureEditSave uploads the edited file. Strict mode uses If-Match with the
// ETag from when the edit was opened. The session stays open: close it with
// SecureEditClose.
func (s *Service) SecureEditSave(ctx context.Context, id string, mode SaveBackMode) error {
	const op = "SecureEditSave"
	es, err := s.editByID(op, id)
	if err != nil {
		return err
	}
	root, err := s.secureRoot(op, es.rootID)
	if err != nil {
		return err
	}
	run, err := s.newSecureRun(ctx, op, root)
	if err != nil {
		return err
	}
	changed, newHash := es.changed()
	if !changed {
		return nil
	}
	// putFile reads the file under the root's local folder; stage the edit there
	// only when the local copy is the version that was opened, else upload from
	// the private folder through a root-shaped shim.
	target, rel := es.rel, es.rel
	if mode == SaveKeepBoth {
		dev, _ := s.SecureDevice()
		rel = vsync.ConflictName(es.rel, dev.ID, time.Now())
		target = rel
	}
	ro, _, err := run.headRemote(ctx, es.rel)
	if err != nil {
		return err
	}
	shim := run.root
	shim.Local = es.dir
	// putFile addresses files by rel under root.Local: point it at the edit file.
	run.root = shim
	stage := filepath.Join(es.dir, filepath.FromSlash(target))
	if stage != es.file {
		if err := os.MkdirAll(filepath.Dir(stage), 0o700); err != nil {
			return classify(op, err)
		}
		if err := copyFile(es.file, stage); err != nil {
			return classify(op, err)
		}
		defer os.Remove(stage)
	}
	var ifMatch string
	create := false
	switch mode {
	case SaveStrict:
		ifMatch = es.etag
	case SaveOverwrite:
		if cur, ok, herr := run.headRemote(ctx, es.rel); herr == nil && ok {
			ifMatch = cur.etag
		} else {
			create = true
		}
	case SaveKeepBoth:
		create, ro = true, remoteObj{}
	default:
		return invalid(op, "unknown save-back mode %q", mode)
	}
	if mode == SaveStrict && ro.key != "" && ro.etag != es.etag {
		return opErr(op, ErrConflict, "%q changed in the vault while you were editing; save as a conflict copy, overwrite, or reopen", es.rel)
	}
	etag, _, err := run.putFile(ctx, rel, ro, ifMatch, create)
	if err != nil {
		if isPrecondition(err) {
			return opErr(op, ErrConflict, "%q changed in the vault while you were editing; save as a conflict copy, overwrite, or reopen", es.rel)
		}
		return classify(op, err)
	}
	if mode != SaveKeepBoth {
		es.etag, es.hash = etag, newHash
		s.syncLocalAfterEdit(run, root, es, etag, newHash)
	}
	return nil
}

// syncLocalAfterEdit updates the local copy and its base when the local file
// is still the version that was opened.
func (s *Service) syncLocalAfterEdit(run *secureRun, root SecureRoot, es *editSession, etag, hash string) {
	local := filepath.Join(root.Local, filepath.FromSlash(es.rel))
	base, ok := run.ix.Get(es.rel)
	cur, err := hashFile(local)
	if !ok || err != nil || cur != base.Hash {
		return // the local copy moved on or does not exist: the next sync decides
	}
	if err := copyFile(es.file, local); err != nil {
		return
	}
	if fi, err := os.Stat(local); err == nil {
		run.ix.Set(es.rel, vsync.Entry{ETag: etag, Hash: hash, Size: fi.Size(), MTime: fi.ModTime().UnixNano()})
		_ = run.ix.Save()
	}
}

func copyFile(src, dst string) error {
	b, err := os.ReadFile(src)
	if err != nil {
		return err
	}
	tmp := dst + ".securepail-tmp"
	if err := os.WriteFile(tmp, b, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, dst)
}

// SecureEditClose ends a session: the plaintext is overwritten and removed.
func (s *Service) SecureEditClose(id string) error {
	es, err := s.editByID("SecureEditClose", id)
	if err != nil {
		return err
	}
	s.sec.mu.Lock()
	delete(s.sec.edits, id)
	s.sec.mu.Unlock()
	wipeDir(es.dir)
	return nil
}

// closeAllEdits wipes every open session (shutdown).
func (s *Service) closeAllEdits() {
	if !s.sec.loadd {
		return
	}
	s.sec.mu.Lock()
	list := s.sec.edits
	s.sec.edits = map[string]*editSession{}
	s.sec.mu.Unlock()
	for _, es := range list {
		wipeDir(es.dir)
	}
}

// wipeDir overwrites the files below dir with zeros, then removes dir.
func wipeDir(dir string) {
	_ = filepath.WalkDir(dir, func(p string, d os.DirEntry, err error) error {
		if err == nil && d.Type().IsRegular() {
			if fi, e := os.Stat(p); e == nil {
				if f, e := os.OpenFile(p, os.O_WRONLY, 0); e == nil {
					buf := make([]byte, 32<<10)
					for left := fi.Size(); left > 0; {
						n := int64(len(buf))
						if left < n {
							n = left
						}
						f.Write(buf[:n])
						left -= n
					}
					f.Sync()
					f.Close()
				}
			}
		}
		return nil
	})
	os.RemoveAll(dir)
}
