package app

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/jstdlee/securePail/internal/vsync"
)

// SecureResolve settles one conflicted path. It looks at the current state of
// both sides, so an out-of-date conflict list cannot cause a wrong write; all
// remote writes are conditional. The returned text says what was done.
func (s *Service) SecureResolve(ctx context.Context, rootID, rel string, res vsync.Resolution) (string, error) {
	const op = "SecureResolve"
	if !res.Valid() {
		return "", invalid(op, "unknown resolution %q", res)
	}
	root, err := s.secureRoot(op, rootID)
	if err != nil {
		return "", err
	}
	unlock, err := s.lockRoot(op, root.ID)
	if err != nil {
		return "", err
	}
	defer unlock()
	run, err := s.newSecureRun(ctx, op, root)
	if err != nil {
		return "", err
	}
	msg, err := run.resolve(ctx, rel, res)
	if errors.Is(err, errRetry) {
		return "", opErr(op, ErrConflict, "%q changed again while resolving; review the conflict again", rel)
	}
	if err != nil {
		return "", err
	}
	if err := run.ix.Save(); err != nil {
		return "", classify(op, err)
	}
	return msg, nil
}

func (r *secureRun) resolve(ctx context.Context, rel string, res vsync.Resolution) (string, error) {
	ro, haveRemote, err := r.headRemote(ctx, rel)
	if err != nil {
		return "", err
	}
	lf, haveLocal := r.statLocal(rel)
	base, hasBase := r.ix.Get(rel)
	l := vsync.Local{Exists: haveLocal}
	if haveLocal && hasBase {
		if l.Changed, _, err = r.localChanged(rel, lf, base); err != nil {
			return "", classify(r.op, err)
		}
	}
	step := vsync.Decide(l, vsync.Remote{Exists: haveRemote, ETag: ro.etag}, vsync.Base{Exists: hasBase, ETag: base.ETag})
	switch step.Op {
	case vsync.OpConflict:
	case vsync.OpCheckSame:
		// Both sides changed: it is only a conflict if the content differs.
		before := len(r.rep.Conflicts)
		if err := r.checkSame(ctx, rel, ro, lf); err != nil {
			return "", err
		}
		if len(r.rep.Conflicts) == before {
			return "both sides already have the same content", nil
		}
	default:
		return fmt.Sprintf("%s is not in conflict (a normal sync will %s it)", rel, step.Op), nil
	}
	if res == vsync.Skip {
		return "left as it is", nil
	}
	if res == vsync.KeepNewest {
		switch {
		case haveLocal && haveRemote:
			res = vsync.Newest(lf.mtime, ro.mtime)
		case haveLocal:
			res = vsync.OverwriteRemote // the remote copy is gone: keep the file that exists
		default:
			res = vsync.OverwriteLocal
		}
	}
	switch res {
	case vsync.OverwriteRemote:
		if !haveLocal {
			if !haveRemote {
				return "nothing to do", nil
			}
			if err := r.trashRemote(ctx, ro); err != nil {
				return "", err
			}
			r.ix.Delete(rel)
			return "deleted on the remote (moved to the vault trash)", nil
		}
		etag, hash, err := r.putFile(ctx, rel, ro, ro.etag, !haveRemote)
		if err != nil {
			if isPrecondition(err) {
				return "", errRetry
			}
			return "", classify(r.op, err)
		}
		r.recordLocal(rel, etag, hash, lf)
		return "the local version replaced the remote one", nil
	case vsync.OverwriteLocal:
		if !haveRemote {
			if !haveLocal {
				return "nothing to do", nil
			}
			if err := r.trashLocal(rel, lf); err != nil {
				return "", err
			}
			return "deleted locally (moved to the trash)", nil
		}
		if err := r.download(ctx, rel, ro, lf, haveLocal); err != nil {
			return "", err
		}
		return "the remote version replaced the local one", nil
	case vsync.KeepBoth:
		switch {
		case haveLocal && haveRemote:
			dst := r.freeConflictName(rel)
			from := filepath.Join(r.root.Local, filepath.FromSlash(rel))
			to := filepath.Join(r.root.Local, filepath.FromSlash(dst))
			if err := os.Rename(from, to); err != nil {
				return "", classify(r.op, err)
			}
			if err := r.download(ctx, rel, ro, localFile{}, false); err != nil {
				_ = os.Rename(to, from) // put the user's file back
				return "", err
			}
			return "kept both: your version is now " + dst + " (the next sync uploads it)", nil
		case haveLocal: // remote deleted: keep the file that exists
			return r.resolve(ctx, rel, vsync.OverwriteRemote)
		case haveRemote:
			return r.resolve(ctx, rel, vsync.OverwriteLocal)
		}
	}
	return "nothing to do", nil
}

func (r *secureRun) freeConflictName(rel string) string {
	for i := 0; ; i++ {
		at := time.Now()
		name := vsync.ConflictName(rel, r.dev.ID, at)
		if i > 0 {
			name = vsync.ConflictName(rel, fmt.Sprintf("%s-%d", r.dev.ID, i+1), at)
		}
		if _, err := os.Lstat(filepath.Join(r.root.Local, filepath.FromSlash(name))); err != nil {
			return name
		}
	}
}

// SecureWatch synchronises a root every interval until ctx ends. onResult gets
// every report (also failed ones). A sync that is still running is not
// started twice. This is the "keep it in sync" mode for a long-running
// process; there is no OS file watching, so local changes are picked up at
// the next interval.
func (s *Service) SecureWatch(ctx context.Context, rootID string, interval time.Duration, onResult func(SecureSyncReport, error)) error {
	if interval < time.Second {
		interval = time.Second
	}
	if _, err := s.secureRoot("SecureWatch", rootID); err != nil {
		return err
	}
	t := time.NewTimer(0)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return nil
		case <-t.C:
			rep, err := s.SecureSync(ctx, rootID, false)
			if onResult != nil && ctx.Err() == nil {
				onResult(rep, err)
			}
			t.Reset(interval)
		}
	}
}
