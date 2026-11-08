// Package vsync holds the pure parts of two-way vault sync: the three-way
// planner, the base index and conflict naming. It does no I/O except for
// the index file, so the rules can be read and tested on their own.
//
// A sync compares, for each path, the local file, the remote object and the
// base: what both looked like after the last successful sync of this path.
// "Local changed" means the content hash differs from the base hash. "Remote
// changed" means the ETag differs from the base ETag. ETags are opaque
// versions here, never content hashes.
package vsync

import (
	"path"
	"strings"
	"time"
)

// Local is the state of the local file.
type Local struct {
	Exists bool
	// Changed: the content hash differs from the base hash. Only meaningful
	// when a base exists; without a base the file is new.
	Changed bool
}

// Remote is the state of the remote object.
type Remote struct {
	Exists bool
	ETag   string
}

// Base is what the last successful sync recorded.
type Base struct {
	Exists bool
	ETag   string
}

// Op is what to do for one path.
type Op int

// Operations.
const (
	// OpNone: in sync, nothing to do.
	OpNone Op = iota
	// OpUpload: send the local file. With IfMatch set, only if the remote
	// still has that ETag; with IfNoneMatch, only if the key does not exist.
	OpUpload
	// OpDownload: replace/create the local file from the remote object.
	OpDownload
	// OpCheckSame: both sides changed. Fetch the remote content and compare
	// it with the local hash: equal means record a new base, different means
	// a conflict. (Encrypted objects differ in ciphertext even when the
	// plaintext is the same, so only a fetch can tell.)
	OpCheckSame
	// OpTrashRemote: deleted locally, unchanged remotely: move the remote to
	// the vault trash.
	OpTrashRemote
	// OpTrashLocal: deleted remotely, unchanged locally: move the local file
	// to the OS trash.
	OpTrashLocal
	// OpForget: gone on both sides: drop the base record.
	OpForget
	// OpConflict: the user has to decide.
	OpConflict
)

func (o Op) String() string {
	return [...]string{"none", "upload", "download", "check-same", "trash-remote", "trash-local", "forget", "conflict"}[o]
}

// ConflictKind says why a path is in conflict.
type ConflictKind string

// Conflict kinds.
const (
	BothNew                   ConflictKind = "both-new"
	BothChanged               ConflictKind = "both-changed"
	LocalDeletedRemoteChanged ConflictKind = "local-deleted-remote-changed"
	LocalChangedRemoteDeleted ConflictKind = "local-changed-remote-deleted"
)

// Step is the plan for one path.
type Step struct {
	Op Op
	// IfMatch is the remote ETag an upload must still find (replace).
	IfMatch string
	// IfNoneMatch: the upload must create the key (it did not exist).
	IfNoneMatch bool
	Conflict    ConflictKind // with OpConflict
}

// Decide is the three-way table.
func Decide(l Local, r Remote, b Base) Step {
	rc := b.Exists && r.Exists && r.ETag != b.ETag
	switch {
	case !b.Exists:
		switch {
		case l.Exists && r.Exists:
			return Step{Op: OpCheckSame}
		case l.Exists:
			return Step{Op: OpUpload, IfNoneMatch: true}
		case r.Exists:
			return Step{Op: OpDownload}
		}
		return Step{Op: OpNone}
	case l.Exists && r.Exists:
		switch {
		case !l.Changed && !rc:
			return Step{Op: OpNone}
		case l.Changed && !rc:
			return Step{Op: OpUpload, IfMatch: r.ETag}
		case !l.Changed && rc:
			return Step{Op: OpDownload}
		}
		return Step{Op: OpCheckSame}
	case !l.Exists && r.Exists:
		if r.ETag == b.ETag {
			return Step{Op: OpTrashRemote}
		}
		return Step{Op: OpConflict, Conflict: LocalDeletedRemoteChanged}
	case l.Exists && !r.Exists:
		if !l.Changed {
			return Step{Op: OpTrashLocal}
		}
		return Step{Op: OpConflict, Conflict: LocalChangedRemoteDeleted}
	}
	return Step{Op: OpForget}
}

// ConflictName is the name a "keep both" copy gets:
// "notes (conflict laptop 2026-11-08).md". Directories are kept.
func ConflictName(rel, device string, at time.Time) string {
	dir, file := path.Split(rel)
	ext := path.Ext(file)
	stem := strings.TrimSuffix(file, ext)
	if stem == "" { // dotfile such as ".env"
		stem, ext = file, ""
	}
	device = strings.Map(func(r rune) rune {
		if r == '/' || r == '\\' || r == ':' || r < 0x20 {
			return '-'
		}
		return r
	}, device)
	return dir + stem + " (conflict " + device + " " + at.UTC().Format("2006-01-02") + ")" + ext
}

// Resolution is the user's decision for a conflict.
type Resolution string

// Resolutions.
const (
	KeepBoth        Resolution = "keep-both"
	OverwriteRemote Resolution = "overwrite-remote"
	OverwriteLocal  Resolution = "overwrite-local"
	KeepNewest      Resolution = "keep-newest"
	Skip            Resolution = "skip"
)

// Valid reports whether r is a known resolution.
func (r Resolution) Valid() bool {
	switch r {
	case KeepBoth, OverwriteRemote, OverwriteLocal, KeepNewest, Skip:
		return true
	}
	return false
}

// Newest turns KeepNewest into OverwriteRemote or OverwriteLocal by modification
// time (ties keep the local file, which is never lost that way).
func Newest(localM, remoteM time.Time) Resolution {
	if remoteM.After(localM) {
		return OverwriteLocal
	}
	return OverwriteRemote
}
