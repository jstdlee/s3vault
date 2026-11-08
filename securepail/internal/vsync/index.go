package vsync

import (
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"sync"
)

// Entry is the base record of one path.
type Entry struct {
	ETag   string `json:"etag"`
	Hash   string `json:"hash"` // hex SHA-256 of the plaintext
	Size   int64  `json:"size"`
	MTime  int64  `json:"mtime"`            // local modification time, UnixNano, when Hash was taken
	Remote string `json:"remote,omitempty"` // object key last seen (differs by suffix when encryption changes)
}

// Index is the base of one sync root. It is a JSON file written atomically.
type Index struct {
	mu      sync.Mutex
	path    string
	Entries map[string]Entry `json:"entries"`
}

// LoadIndex reads the index file; a missing file is an empty index. A file
// that cannot be parsed is an error: guessing would lose or duplicate data.
func LoadIndex(path string) (*Index, error) {
	ix := &Index{path: path, Entries: map[string]Entry{}}
	b, err := os.ReadFile(path)
	if errors.Is(err, fs.ErrNotExist) {
		return ix, nil
	}
	if err != nil {
		return nil, err
	}
	if err := json.Unmarshal(b, ix); err != nil {
		return nil, fmt.Errorf("sync index %s is damaged: %w", path, err)
	}
	if ix.Entries == nil {
		ix.Entries = map[string]Entry{}
	}
	return ix, nil
}

// Get returns the base of rel.
func (ix *Index) Get(rel string) (Entry, bool) {
	ix.mu.Lock()
	defer ix.mu.Unlock()
	e, ok := ix.Entries[rel]
	return e, ok
}

// Set records a base.
func (ix *Index) Set(rel string, e Entry) {
	ix.mu.Lock()
	ix.Entries[rel] = e
	ix.mu.Unlock()
}

// Delete forgets rel.
func (ix *Index) Delete(rel string) {
	ix.mu.Lock()
	delete(ix.Entries, rel)
	ix.mu.Unlock()
}

// Paths returns the known paths, sorted.
func (ix *Index) Paths() []string {
	ix.mu.Lock()
	defer ix.mu.Unlock()
	out := make([]string, 0, len(ix.Entries))
	for p := range ix.Entries {
		out = append(out, p)
	}
	sort.Strings(out)
	return out
}

// Save writes the index atomically.
func (ix *Index) Save() error {
	ix.mu.Lock()
	b, err := json.MarshalIndent(ix, "", " ")
	ix.mu.Unlock()
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(ix.path), 0o700); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(filepath.Dir(ix.path), ".vsync-*")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name())
	if _, err := tmp.Write(b); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmp.Name(), ix.path)
}
