package app

import (
	"context"
	"sort"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/s3"

	"github.com/jstdlee/securePail/internal/storage"
)

// SecureTrashItem is one soft-deleted object.
type SecureTrashItem struct {
	// Key is the trash object key; pass it to SecureTrashRestore.
	Key string `json:"key"`
	// Path is the logical path the file had in the root.
	Path    string    `json:"path"`
	Deleted time.Time `json:"deleted"`
	Size    int64     `json:"size"`
}

func parseTrashKey(root SecureRoot, key string) (path string, at time.Time, ok bool) {
	rest := strings.TrimPrefix(key, root.Prefix+secureTrashDir)
	i := strings.IndexByte(rest, '/')
	if i <= 0 || i == len(rest)-1 {
		return "", time.Time{}, false
	}
	at, err := time.Parse("20060102T150405Z", rest[:i])
	if err != nil {
		return "", time.Time{}, false
	}
	objRel := rest[i+1:]
	if root.Method != "" {
		if sfx := root.suffix(); strings.HasSuffix(objRel, sfx) {
			objRel = strings.TrimSuffix(objRel, sfx)
		}
	}
	return objRel, at, true
}

// SecureTrashList lists the remote trash of a root, newest first.
func (s *Service) SecureTrashList(ctx context.Context, rootID string) ([]SecureTrashItem, error) {
	const op = "SecureTrashList"
	root, err := s.secureRoot(op, rootID)
	if err != nil {
		return nil, err
	}
	c, err := s.bucketClient(ctx, op, Location{AccountID: root.AccountID, Bucket: root.Bucket})
	if err != nil {
		return nil, err
	}
	return s.listTrash(ctx, c, root)
}

func (s *Service) listTrash(ctx context.Context, c *storage.Client, root SecureRoot) ([]SecureTrashItem, error) {
	var out []SecureTrashItem
	p := s3.NewListObjectsV2Paginator(c.S3(), &s3.ListObjectsV2Input{Bucket: aws.String(root.Bucket), Prefix: aws.String(root.Prefix + secureTrashDir)})
	for p.HasMorePages() {
		page, err := p.NextPage(ctx)
		if err != nil {
			return nil, classify("SecureTrash", err)
		}
		for _, o := range page.Contents {
			key := aws.ToString(o.Key)
			if rel, at, ok := parseTrashKey(root, key); ok {
				out = append(out, SecureTrashItem{Key: key, Path: rel, Deleted: at, Size: aws.ToInt64(o.Size)})
			}
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Deleted.After(out[j].Deleted) })
	return out, nil
}

// SecureTrashRestore puts a trashed object back at its original key. It
// refuses when something else has taken the place; the next sync downloads it.
func (s *Service) SecureTrashRestore(ctx context.Context, rootID, trashKey string) error {
	const op = "SecureTrashRestore"
	root, err := s.secureRoot(op, rootID)
	if err != nil {
		return err
	}
	if !strings.HasPrefix(trashKey, root.Prefix+secureTrashDir) {
		return invalid(op, "not a trash object of this root")
	}
	c, err := s.bucketClient(ctx, op, Location{AccountID: root.AccountID, Bucket: root.Bucket})
	if err != nil {
		return err
	}
	if _, _, ok := parseTrashKey(root, trashKey); !ok {
		return invalid(op, "not a trash object of this root")
	}
	rest := strings.TrimPrefix(trashKey, root.Prefix+secureTrashDir)
	orig := root.Prefix + rest[strings.IndexByte(rest, '/')+1:]
	h, err := headObj(ctx, c, op, root.Bucket, trashKey, "")
	if err != nil {
		return err
	}
	in := &s3.CopyObjectInput{Bucket: aws.String(root.Bucket), Key: aws.String(orig), IfNoneMatch: aws.String("*"),
		CopySource: aws.String(storage.CopySource(root.Bucket, trashKey, "")), CopySourceIfMatch: h.ETag}
	if err := c.Copy(ctx, in, aws.ToInt64(h.ContentLength), storage.TransferOptions{}); err != nil {
		if isPrecondition(err) {
			return opErr(op, ErrConflict, "%q exists again; restore it under another name by downloading the trash object", orig)
		}
		return classify(op, err)
	}
	c.DeleteObjects(ctx, root.Bucket, []storage.ObjectID{{Key: trashKey}})
	return nil
}

// purgeTrash deletes trash older than the root's retention. Failures only
// warn: a stale trash object is harmless.
func (r *secureRun) purgeTrash(ctx context.Context) {
	items, err := r.s.listTrash(ctx, r.c, r.root)
	if err != nil {
		r.warn("could not list the trash: %v", err)
		return
	}
	cutoff := time.Now().AddDate(0, 0, -r.root.trashDays())
	var ids []storage.ObjectID
	for _, it := range items {
		if it.Deleted.Before(cutoff) {
			ids = append(ids, storage.ObjectID{Key: it.Key})
		}
	}
	if len(ids) > 0 {
		r.c.DeleteObjects(ctx, r.root.Bucket, ids)
	}
}

// SecureTrashPurge deletes the trash objects older than days (0: the root's
// retention) and returns how many went.
func (s *Service) SecureTrashPurge(ctx context.Context, rootID string, days int) (int, error) {
	const op = "SecureTrashPurge"
	root, err := s.secureRoot(op, rootID)
	if err != nil {
		return 0, err
	}
	if days <= 0 {
		days = root.trashDays()
	}
	c, err := s.bucketClient(ctx, op, Location{AccountID: root.AccountID, Bucket: root.Bucket})
	if err != nil {
		return 0, err
	}
	items, err := s.listTrash(ctx, c, root)
	if err != nil {
		return 0, err
	}
	cutoff := time.Now().AddDate(0, 0, -days)
	var ids []storage.ObjectID
	for _, it := range items {
		if it.Deleted.Before(cutoff) {
			ids = append(ids, storage.ObjectID{Key: it.Key})
		}
	}
	if len(ids) > 0 {
		c.DeleteObjects(ctx, root.Bucket, ids)
	}
	return len(ids), nil
}
