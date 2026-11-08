package app

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/s3"

	"github.com/jstdlee/securePail/internal/rules"
	"github.com/jstdlee/securePail/internal/safepath"
	"github.com/jstdlee/securePail/internal/storage"
	"github.com/jstdlee/securePail/internal/trash"
	"github.com/jstdlee/securePail/internal/vsync"
)

// moveToTrash puts a local file in the OS trash; tests replace it.
var moveToTrash = trash.MoveToTrash

// SecureFileInfo describes one side of a conflict.
type SecureFileInfo struct {
	Size  int64     `json:"size"`
	MTime time.Time `json:"mtime"`
	Hash  string    `json:"hash,omitempty"` // short SHA-256 of the plaintext, local side only
}

// SecureConflict is a path that needs a decision.
type SecureConflict struct {
	Path   string          `json:"path"`
	Kind   string          `json:"kind"`
	Local  *SecureFileInfo `json:"local,omitempty"`
	Remote *SecureFileInfo `json:"remote,omitempty"`
}

// SecureAction is the outcome for one path.
type SecureAction struct {
	Path string `json:"path"`
	Op   string `json:"op"`
	Err  string `json:"err,omitempty"`
	Note string `json:"note,omitempty"`
}

// SecureSyncReport is the result of one sync (or, with DryRun, its plan).
type SecureSyncReport struct {
	DryRun    bool             `json:"dryRun,omitempty"`
	Actions   []SecureAction   `json:"actions"`
	Conflicts []SecureConflict `json:"conflicts"`
	Warnings  []string         `json:"warnings,omitempty"`
}

// Count returns how many actions had the given op and no error.
func (r SecureSyncReport) Count(op string) int {
	n := 0
	for _, a := range r.Actions {
		if a.Op == op && a.Err == "" {
			n++
		}
	}
	return n
}

// Errors returns the failed actions.
func (r SecureSyncReport) Errors() []SecureAction {
	var out []SecureAction
	for _, a := range r.Actions {
		if a.Err != "" {
			out = append(out, a)
		}
	}
	return out
}

type remoteObj struct {
	key, etag string
	size      int64
	mtime     time.Time
	enc       bool
}

type localFile struct {
	size  int64
	mtime time.Time
}

type secureRun struct {
	s    *Service
	op   string
	root SecureRoot
	c    *storage.Client
	ix   *vsyncIndex
	dev  Device
	sc   *secureCtx // nil for plain roots
	dry  bool

	mu  sync.Mutex
	rep SecureSyncReport
}

// vsyncIndex is vsync.Index; the alias keeps this file's signatures short.
type vsyncIndex = vsync.Index

var errRetry = errors.New("retry")

func (s *Service) newSecureRun(ctx context.Context, op string, root SecureRoot) (*secureRun, error) {
	if err := s.loadSecure(); err != nil {
		return nil, classify(op, err)
	}
	c, err := s.bucketClient(ctx, op, Location{AccountID: root.AccountID, Bucket: root.Bucket})
	if err != nil {
		return nil, err
	}
	ix, err := vsync.LoadIndex(s.indexPath(root))
	if err != nil {
		return nil, classify(op, err)
	}
	r := &secureRun{s: s, op: op, root: root, c: c, ix: ix, dev: s.sec.dev}
	if root.Method != "" {
		sc, err := s.validateSecureOpts(ctx, op, &rules.Secure{Method: root.Method, KeyRef: root.KeyRef})
		if err != nil {
			return nil, err
		}
		r.sc = sc
	}
	if fi, err := os.Stat(root.Local); err != nil || !fi.IsDir() {
		return nil, invalid(op, "the local folder %s does not exist", root.Local)
	}
	return r, nil
}

// lockRoot allows one sync of a root at a time.
func (s *Service) lockRoot(op, id string) (func(), error) {
	st := &s.sec
	st.mu.Lock()
	defer st.mu.Unlock()
	if st.running[id] {
		return nil, opErr(op, ErrConflict, "this root is already being synchronised")
	}
	st.running[id] = true
	return func() { st.mu.Lock(); delete(st.running, id); st.mu.Unlock() }, nil
}

// SecureSync synchronises one root now. With dryRun nothing is changed: the
// report lists what a sync would do and which paths are in conflict.
func (s *Service) SecureSync(ctx context.Context, rootID string, dryRun bool) (SecureSyncReport, error) {
	const op = "SecureSync"
	root, err := s.secureRoot(op, rootID)
	if err != nil {
		return SecureSyncReport{}, err
	}
	unlock, err := s.lockRoot(op, root.ID)
	if err != nil {
		return SecureSyncReport{}, err
	}
	defer unlock()
	run, err := s.newSecureRun(ctx, op, root)
	if err != nil {
		return SecureSyncReport{}, err
	}
	run.dry = dryRun
	run.rep.DryRun = dryRun
	if err := run.sync(ctx); err != nil {
		return run.rep, err
	}
	return run.rep, nil
}

func (r *secureRun) note(a SecureAction) {
	r.mu.Lock()
	r.rep.Actions = append(r.rep.Actions, a)
	r.mu.Unlock()
}

func (r *secureRun) warn(format string, a ...any) {
	r.mu.Lock()
	r.rep.Warnings = append(r.rep.Warnings, fmt.Sprintf(format, a...))
	r.mu.Unlock()
}

func (r *secureRun) sync(ctx context.Context) error {
	if !r.dry {
		if err := r.ensureMeta(ctx); err != nil {
			return err
		}
	}
	remote, err := r.listRemote(ctx)
	if err != nil {
		return err
	}
	local, err := r.scanLocal()
	if err != nil {
		return classify(r.op, err)
	}
	paths := map[string]bool{}
	for p := range remote {
		paths[p] = true
	}
	for p := range local {
		paths[p] = true
	}
	for _, p := range r.ix.Paths() {
		paths[p] = true
	}
	order := sortedKeys(paths)
	work := make(chan string)
	var wg sync.WaitGroup
	for i := 0; i < 4; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for rel := range work {
				if ctx.Err() != nil {
					continue
				}
				r.syncPath(ctx, rel, remote[rel], local[rel])
			}
		}()
	}
	for _, p := range order {
		work <- p
	}
	close(work)
	wg.Wait()
	if err := ctx.Err(); err != nil {
		return err
	}
	if !r.dry {
		if err := r.ix.Save(); err != nil {
			return classify(r.op, err)
		}
		r.purgeTrash(ctx)
	}
	sortReport(&r.rep)
	return nil
}

func sortReport(rep *SecureSyncReport) {
	sort.Slice(rep.Actions, func(i, j int) bool { return rep.Actions[i].Path < rep.Actions[j].Path })
	sort.Slice(rep.Conflicts, func(i, j int) bool { return rep.Conflicts[i].Path < rep.Conflicts[j].Path })
}

// ---- listing and scanning ---------------------------------------------------

func (r *secureRun) listRemote(ctx context.Context) (map[string]remoteObj, error) {
	out := map[string]remoteObj{}
	stray := map[string]bool{}
	p := s3.NewListObjectsV2Paginator(r.c.S3(), &s3.ListObjectsV2Input{Bucket: aws.String(r.root.Bucket), Prefix: aws.String(r.root.Prefix)})
	for p.HasMorePages() {
		page, err := p.NextPage(ctx)
		if err != nil {
			return nil, classify(r.op, err)
		}
		for _, o := range page.Contents {
			key := aws.ToString(o.Key)
			rel, enc, ok := r.root.logicalPath(key)
			if !ok {
				continue
			}
			if err := safepath.ValidKey(rel); err != nil || r.root.excluded(rel) {
				if err != nil {
					r.warn("skipped remote object %q: %v", key, err)
				}
				continue
			}
			obj := remoteObj{key: key, etag: aws.ToString(o.ETag), size: aws.ToInt64(o.Size), mtime: aws.ToTime(o.LastModified), enc: enc}
			if prev, dup := out[rel]; dup {
				// a.txt and a.txt.spe in one encrypted root: keep the one that matches the root's rule.
				want := r.root.encrypted(rel)
				if prev.enc == want {
					r.warn("ignored %q: %q is the object for %q", key, prev.key, rel)
				} else if obj.enc == want {
					r.warn("ignored %q: %q is the object for %q", prev.key, key, rel)
					out[rel] = obj
				} else {
					stray[rel] = true
				}
				continue
			}
			out[rel] = obj
		}
	}
	for rel := range stray {
		r.warn("%q exists both encrypted and plain; neither is synchronised until you remove one", rel)
		delete(out, rel)
	}
	return out, nil
}

func (r *secureRun) scanLocal() (map[string]localFile, error) {
	out := map[string]localFile{}
	err := filepath.WalkDir(r.root.Local, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			if p == r.root.Local {
				return err
			}
			r.warn("cannot read %s: %v", p, err)
			return nil
		}
		if d.IsDir() {
			return nil
		}
		rel, rerr := filepath.Rel(r.root.Local, p)
		if rerr != nil {
			return nil
		}
		rel = filepath.ToSlash(rel)
		if r.root.excluded(rel) || strings.HasPrefix(path.Base(rel), ".securepail-tmp") {
			return nil
		}
		if !d.Type().IsRegular() {
			r.warn("skipped %s: not a regular file", rel)
			return nil
		}
		if len(r.root.remoteKey(rel)) > maxKeyBytes {
			r.warn("skipped %s: the object key would be too long", rel)
			return nil
		}
		fi, err := d.Info()
		if err != nil {
			return nil
		}
		out[rel] = localFile{size: fi.Size(), mtime: fi.ModTime()}
		return nil
	})
	return out, err
}

func hashFile(p string) (string, error) {
	f, err := os.Open(p)
	if err != nil {
		return "", err
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

// localChanged decides whether the content differs from the base, hashing only
// when size or modification time moved.
func (r *secureRun) localChanged(rel string, lf localFile, base vsync.Entry) (bool, string, error) {
	if base.Size == lf.size && base.MTime == lf.mtime.UnixNano() && base.Hash != "" {
		return false, base.Hash, nil
	}
	h, err := hashFile(filepath.Join(r.root.Local, filepath.FromSlash(rel)))
	if err != nil {
		return false, "", err
	}
	if h == base.Hash {
		base.MTime, base.Size = lf.mtime.UnixNano(), lf.size
		r.ix.Set(rel, base) // remember the new stat so the next run skips hashing
		return false, h, nil
	}
	return true, h, nil
}

// ---- one path ---------------------------------------------------------------

func (r *secureRun) syncPath(ctx context.Context, rel string, ro remoteObj, lf localFile) {
	_, haveRemote := r.remoteExists(ro)
	haveLocal := lf.size >= 0 && !lf.mtime.IsZero()
	for attempt := 0; attempt < 4; attempt++ {
		if attempt > 0 {
			// Lost a race: look at the current state of both sides.
			var err error
			if ro, haveRemote, err = r.headRemote(ctx, rel); err != nil {
				r.note(SecureAction{Path: rel, Op: "error", Err: err.Error()})
				return
			}
			var ok bool
			if lf, ok = r.statLocal(rel); ok {
				haveLocal = true
			} else {
				haveLocal = false
			}
		}
		base, hasBase := r.ix.Get(rel)
		l := vsync.Local{Exists: haveLocal}
		var hash string
		if haveLocal && hasBase {
			ch, h, err := r.localChanged(rel, lf, base)
			if err != nil {
				r.note(SecureAction{Path: rel, Op: "error", Err: err.Error()})
				return
			}
			l.Changed, hash = ch, h
		}
		step := vsync.Decide(l, vsync.Remote{Exists: haveRemote, ETag: ro.etag}, vsync.Base{Exists: hasBase, ETag: base.ETag})
		err := r.apply(ctx, rel, step, ro, lf, hash, haveLocal)
		if errors.Is(err, errRetry) {
			continue
		}
		if err != nil {
			r.note(SecureAction{Path: rel, Op: step.Op.String(), Err: err.Error()})
		}
		return
	}
	r.note(SecureAction{Path: rel, Op: "error", Err: "changed again while syncing; it will be retried on the next sync"})
}

func (r *secureRun) remoteExists(ro remoteObj) (remoteObj, bool) { return ro, ro.key != "" }

func (r *secureRun) statLocal(rel string) (localFile, bool) {
	fi, err := os.Lstat(filepath.Join(r.root.Local, filepath.FromSlash(rel)))
	if err != nil || !fi.Mode().IsRegular() {
		return localFile{}, false
	}
	return localFile{size: fi.Size(), mtime: fi.ModTime()}, true
}

// headRemote looks up the object for rel under the key the root maps it to,
// or under the other spelling (plain vs encrypted) when that one is absent.
func (r *secureRun) headRemote(ctx context.Context, rel string) (remoteObj, bool, error) {
	keys := []string{r.root.remoteKey(rel)}
	if r.root.Method != "" {
		other := r.root.Prefix + rel
		if r.root.encrypted(rel) {
			keys = append(keys, other)
		} else {
			keys = append(keys, other+r.root.suffix())
		}
	}
	for _, k := range keys {
		h, err := headRemoteMeta2(ctx, r.c, r.root.Bucket, k)
		if err != nil {
			return remoteObj{}, false, err
		}
		if h != nil {
			enc := r.root.Method != "" && strings.HasSuffix(k, r.root.suffix()) && k != r.root.Prefix+rel
			return remoteObj{key: k, etag: aws.ToString(h.ETag), size: aws.ToInt64(h.ContentLength),
				mtime: aws.ToTime(h.LastModified), enc: enc}, true, nil
		}
	}
	return remoteObj{}, false, nil
}

func headRemoteMeta2(ctx context.Context, c *storage.Client, bucket, key string) (*s3.HeadObjectOutput, error) {
	h, err := headObj(ctx, c, "HeadObject", bucket, key, "")
	if err != nil {
		if KindOf(err) == ErrNotFound {
			return nil, nil
		}
		return nil, err
	}
	return h, nil
}

func (r *secureRun) apply(ctx context.Context, rel string, step vsync.Step, ro remoteObj, lf localFile, hash string, haveLocal bool) error {
	switch step.Op {
	case vsync.OpNone:
		return nil
	case vsync.OpForget:
		if !r.dry {
			r.ix.Delete(rel)
		}
		return nil
	case vsync.OpConflict:
		r.addConflict(rel, string(step.Conflict), ro, lf, haveLocal, hash)
		return nil
	}
	if r.dry {
		r.note(SecureAction{Path: rel, Op: step.Op.String(), Note: "planned"})
		return nil
	}
	switch step.Op {
	case vsync.OpUpload:
		return r.upload(ctx, rel, step, ro, lf)
	case vsync.OpDownload:
		return r.download(ctx, rel, ro, lf, haveLocal)
	case vsync.OpCheckSame:
		return r.checkSame(ctx, rel, ro, lf)
	case vsync.OpTrashRemote:
		if err := r.trashRemote(ctx, ro); err != nil {
			return err
		}
		r.ix.Delete(rel)
		r.note(SecureAction{Path: rel, Op: "trash-remote"})
	case vsync.OpTrashLocal:
		return r.trashLocal(rel, lf)
	}
	return nil
}

func (r *secureRun) addConflict(rel, kind string, ro remoteObj, lf localFile, haveLocal bool, hash string) {
	c := SecureConflict{Path: rel, Kind: kind}
	if haveLocal {
		c.Local = &SecureFileInfo{Size: lf.size, MTime: lf.mtime, Hash: shortHash(hash)}
	}
	if ro.key != "" {
		c.Remote = &SecureFileInfo{Size: ro.size, MTime: ro.mtime}
	}
	r.mu.Lock()
	r.rep.Conflicts = append(r.rep.Conflicts, c)
	r.mu.Unlock()
}

func shortHash(h string) string {
	if len(h) > 12 {
		return h[:12]
	}
	return h
}

func isPrecondition(err error) bool {
	return err != nil && KindOf(classify("x", err)) == ErrConflict
}

// ---- upload -----------------------------------------------------------------

func (r *secureRun) upload(ctx context.Context, rel string, step vsync.Step, ro remoteObj, lf localFile) error {
	etag, hash, err := r.putFile(ctx, rel, ro, step.IfMatch, step.IfNoneMatch || ro.key == "")
	if err != nil {
		if isPrecondition(err) {
			return errRetry
		}
		return classify(r.op, err)
	}
	r.recordLocal(rel, etag, hash, lf)
	r.note(SecureAction{Path: rel, Op: "upload"})
	return nil
}

// putFile uploads the local file for rel with the given precondition and returns
// the new ETag and the hash of the plaintext that was read before sending. If
// the object lives under another key (encryption setting changed), the new key
// is created and the old object goes to the trash.
func (r *secureRun) putFile(ctx context.Context, rel string, ro remoteObj, ifMatch string, create bool) (etag, hash string, err error) {
	local := filepath.Join(r.root.Local, filepath.FromSlash(rel))
	if hash, err = hashFile(local); err != nil {
		return "", "", err
	}
	key := r.root.remoteKey(rel)
	in := &s3.PutObjectInput{Bucket: aws.String(r.root.Bucket), Key: aws.String(key), Metadata: map[string]string{}}
	moved := ro.key != "" && ro.key != key
	switch {
	case moved || create:
		in.IfNoneMatch = aws.String("*")
	case ifMatch != "":
		in.IfMatch = aws.String(ifMatch)
	}
	var body *os.File
	if r.root.encrypted(rel) {
		in.Metadata[secureMetaKey] = r.root.Method
		in.ContentType = aws.String("application/octet-stream")
		sp, _, serr := r.s.spoolEncrypted(ctx, r.sc, local, !seclayerCompressed(rel))
		if serr != nil {
			return "", "", serr
		}
		defer func() { sp.Close(); os.Remove(sp.Name()) }()
		body = sp
	} else {
		in.ContentType = aws.String(r.s.ContentTypeFor(local))
		f, oerr := os.Open(local)
		if oerr != nil {
			return "", "", oerr
		}
		defer f.Close()
		body = f
	}
	in.Body = body
	out, err := r.c.Upload(ctx, in, storage.TransferOptions{PartSize: r.s.partSize()})
	if err != nil {
		return "", "", err
	}
	if moved {
		if terr := r.trashRemote(ctx, ro); terr != nil {
			r.warn("uploaded %q but could not trash the old object %q: %v", key, ro.key, terr)
		}
	}
	return aws.ToString(out.ETag), hash, nil
}

// recordLocal stores the base after a successful transfer. If the file changed
// while it was read, the stat is left out so the next run hashes it again.
func (r *secureRun) recordLocal(rel, etag, hash string, before localFile) {
	e := vsync.Entry{ETag: etag, Hash: hash, Size: before.size, MTime: before.mtime.UnixNano()}
	if now, ok := r.statLocal(rel); !ok || now.size != before.size || !now.mtime.Equal(before.mtime) {
		e.MTime = 0
	}
	r.ix.Set(rel, e)
}

// ---- download ---------------------------------------------------------------

// fetchPlain downloads ro into a temporary file next to dir and, for encrypted
// objects, decrypts it into a second one. It returns the file holding the
// plaintext, its hash and size; all temporary files are removed by cleanup.
func (r *secureRun) fetchPlain(ctx context.Context, ro remoteObj, dir string) (plain *os.File, hash string, size int64, cleanup func(), err error) {
	var files []*os.File
	cleanup = func() {
		for _, f := range files {
			f.Close()
			os.Remove(f.Name())
		}
	}
	defer func() {
		if err != nil {
			cleanup()
			cleanup = func() {}
		}
	}()
	if err = os.MkdirAll(dir, 0o755); err != nil {
		return
	}
	raw, err := safepath.CreateTemp(dir)
	if err != nil {
		return
	}
	files = append(files, raw)
	in := &s3.GetObjectInput{Bucket: aws.String(r.root.Bucket), Key: aws.String(ro.key), IfMatch: aws.String(ro.etag)}
	if _, err = r.c.Download(ctx, in, raw, storage.TransferOptions{PartSize: r.s.partSize(), Size: ro.size}); err != nil {
		return
	}
	plain = raw
	if ro.enc {
		out, cerr := safepath.CreateTemp(dir)
		if cerr != nil {
			err = cerr
			return
		}
		files = append(files, out)
		if err = r.s.decryptInto(ctx, raw, out, r.root.Method, r.root.KeyRef, 0); err != nil {
			return
		}
		plain = out
	}
	if _, err = plain.Seek(0, io.SeekStart); err != nil {
		return
	}
	h := sha256.New()
	if size, err = io.Copy(h, plain); err != nil {
		return
	}
	hash = hex.EncodeToString(h.Sum(nil))
	return
}

func (r *secureRun) download(ctx context.Context, rel string, ro remoteObj, lf localFile, haveLocal bool) error {
	final := filepath.Join(r.root.Local, filepath.FromSlash(rel))
	plain, hash, size, cleanup, err := r.fetchPlain(ctx, ro, filepath.Dir(final))
	if err != nil {
		if isPrecondition(err) {
			return errRetry
		}
		return r.fetchErr(err)
	}
	defer cleanup()
	if err := r.publish(plain, final, ro.mtime, lf, haveLocal); err != nil {
		return err
	}
	fi, err := os.Stat(final)
	if err != nil {
		return classify(r.op, err)
	}
	r.ix.Set(rel, vsync.Entry{ETag: ro.etag, Hash: hash, Size: size, MTime: fi.ModTime().UnixNano()})
	r.note(SecureAction{Path: rel, Op: "download"})
	return nil
}

func (r *secureRun) fetchErr(err error) error {
	var ae *OpError
	if errors.As(err, &ae) {
		return err
	}
	return classify(r.op, err)
}

// publish replaces the local file with plain, but only if the local file is
// still what the plan saw: a file edited in the meantime is never overwritten.
func (r *secureRun) publish(plain *os.File, final string, mtime time.Time, planned localFile, hadLocal bool) error {
	now, exists := os.Lstat(final)
	switch {
	case hadLocal && exists != nil:
		return errRetry // it vanished: re-plan
	case !hadLocal && exists == nil:
		return errRetry // it appeared: re-plan
	case hadLocal && (now.Size() != planned.size || !now.ModTime().Equal(planned.mtime)):
		return errRetry
	}
	if err := plain.Close(); err != nil {
		return classify(r.op, err)
	}
	if !mtime.IsZero() {
		_ = os.Chtimes(plain.Name(), mtime, mtime)
	}
	if err := safepath.Publish(plain.Name(), final, true); err != nil {
		return classify(r.op, err)
	}
	return nil
}

func (r *secureRun) checkSame(ctx context.Context, rel string, ro remoteObj, lf localFile) error {
	local := filepath.Join(r.root.Local, filepath.FromSlash(rel))
	lh, err := hashFile(local)
	if err != nil {
		return classify(r.op, err)
	}
	if ro.size > maxCheckBytes {
		r.addConflict(rel, string(vsync.BothChanged), ro, lf, true, lh)
		return nil
	}
	plain, rh, _, cleanup, err := r.fetchPlain(ctx, ro, filepath.Dir(local))
	if err != nil {
		if isPrecondition(err) {
			return errRetry
		}
		return r.fetchErr(err)
	}
	defer cleanup()
	_ = plain
	if rh != lh {
		kind := vsync.BothChanged
		if _, has := r.ix.Get(rel); !has {
			kind = vsync.BothNew
		}
		r.addConflict(rel, string(kind), ro, lf, true, lh)
		return nil
	}
	r.recordLocal(rel, ro.etag, lh, lf)
	r.note(SecureAction{Path: rel, Op: "check-same", Note: "same content on both sides"})
	return nil
}

// ---- deletes and trash ------------------------------------------------------

func trashStamp(t time.Time) string { return t.UTC().Format("20060102T150405Z") }

func (r *secureRun) trashKey(objKey string, at time.Time) string {
	return r.root.Prefix + secureTrashDir + trashStamp(at) + "/" + strings.TrimPrefix(objKey, r.root.Prefix)
}

// trashRemote copies the object into the trash (only if it still has the
// ETag we looked at) and then deletes it.
func (r *secureRun) trashRemote(ctx context.Context, ro remoteObj) error {
	return r.s.trashObject(ctx, r.c, r.root, ro.key, ro.etag, ro.size)
}

func (s *Service) trashObject(ctx context.Context, c *storage.Client, root SecureRoot, key, etag string, size int64) error {
	dst := root.Prefix + secureTrashDir + trashStamp(time.Now()) + "/" + strings.TrimPrefix(key, root.Prefix)
	in := &s3.CopyObjectInput{Bucket: aws.String(root.Bucket), Key: aws.String(dst),
		CopySource: aws.String(storage.CopySource(root.Bucket, key, ""))}
	if etag != "" {
		in.CopySourceIfMatch = aws.String(etag)
	}
	if err := c.Copy(ctx, in, size, storage.TransferOptions{}); err != nil {
		if isPrecondition(err) {
			return errRetry
		}
		return classify("Trash", err)
	}
	res := c.DeleteObjects(ctx, root.Bucket, []storage.ObjectID{{Key: key}})
	for _, d := range res {
		if d.Status != storage.DeleteSucceeded {
			return opErr("Trash", ErrOther, "copied %q to the trash but could not delete it: %s", key, d.Message)
		}
	}
	return nil
}

func (r *secureRun) trashLocal(rel string, lf localFile) error {
	local := filepath.Join(r.root.Local, filepath.FromSlash(rel))
	now, err := os.Lstat(local)
	if err != nil || now.Size() != lf.size || !now.ModTime().Equal(lf.mtime) {
		return errRetry
	}
	if err := moveToTrash(local); err != nil {
		return classify(r.op, err)
	}
	r.ix.Delete(rel)
	r.note(SecureAction{Path: rel, Op: "trash-local"})
	return nil
}

// ---- meta -------------------------------------------------------------------

func (r *secureRun) ensureMeta(ctx context.Context) error {
	put := func(key string, data []byte) error {
		h, err := headRemoteMeta2(ctx, r.c, r.root.Bucket, r.root.Prefix+key)
		if err != nil {
			return err
		}
		if h != nil {
			return nil
		}
		_, err = r.c.Upload(ctx, &s3.PutObjectInput{Bucket: aws.String(r.root.Bucket), Key: aws.String(r.root.Prefix + key),
			Body: bytes.NewReader(data), ContentType: aws.String("application/json"), IfNoneMatch: aws.String("*")}, storage.TransferOptions{})
		if err != nil && !isPrecondition(err) {
			return classify(r.op, err)
		}
		return nil
	}
	if err := put(secureMarker, marshalMarker(r.root)); err != nil {
		return err
	}
	dev := fmt.Sprintf(`{"id":%q,"name":%q}`, r.dev.ID, r.dev.Name)
	return put(secureDevDir+r.dev.ID+".json", []byte(dev))
}
