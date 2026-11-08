package app

import (
	"bytes"
	"context"
	"fmt"
	"math/rand"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/jstdlee/securePail/internal/s3test"
	"github.com/jstdlee/securePail/internal/seclayer"
	"github.com/jstdlee/securePail/internal/vsync"
)

// vdev is one simulated device: its own config dir, keyring, local folder and
// account, all pointing at the same in-memory S3 server and sharing one key.
type vdev struct {
	t     *testing.T
	s     *Service
	root  SecureRoot
	local string
}

func newVDevs(t *testing.T, method string, n int) (*s3test.Server, []*vdev) {
	t.Helper()
	srv := s3test.New()
	t.Cleanup(srv.Close)
	srv.CreateBucket("b", false)
	key, err := seclayer.GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	// Moving to the OS trash is replaced by a delete that keeps the content.
	oldTrash := moveToTrash
	osTrash := t.TempDir()
	moveToTrash = func(p string) error {
		return os.Rename(p, filepath.Join(osTrash, fmt.Sprintf("%d-%s", time.Now().UnixNano(), filepath.Base(p))))
	}
	t.Cleanup(func() { moveToTrash = oldTrash })
	var devs []*vdev
	for i := 0; i < n; i++ {
		s := newTestService(t, nil)
		acc, err := s.SaveAccount(staticAccount("mem", srv.URL), &Secrets{SecretAccessKey: "sk"})
		if err != nil {
			t.Fatal(err)
		}
		if err := s.SetSecret("vk", key); err != nil {
			t.Fatal(err)
		}
		local := t.TempDir()
		root, err := s.SaveSecureRoot(SecureRoot{Name: "main", AccountID: acc.ID, Bucket: "b", Prefix: "vault", Local: local,
			Method: method, KeyRef: map[bool]string{true: "vk"}[method != ""]})
		if err != nil {
			t.Fatal(err)
		}
		devs = append(devs, &vdev{t: t, s: s, root: root, local: local})
	}
	return srv, devs
}

func (d *vdev) write(rel, content string) {
	d.t.Helper()
	p := filepath.Join(d.local, filepath.FromSlash(rel))
	if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
		d.t.Fatal(err)
	}
	if err := os.WriteFile(p, []byte(content), 0o644); err != nil {
		d.t.Fatal(err)
	}
	// distinct modification times even on coarse file systems
	at := time.Now().Add(time.Duration(rand.Intn(1000)+1) * time.Second)
	_ = os.Chtimes(p, at, at)
}

func (d *vdev) read(rel string) (string, bool) {
	b, err := os.ReadFile(filepath.Join(d.local, filepath.FromSlash(rel)))
	return string(b), err == nil
}

func (d *vdev) remove(rel string) {
	d.t.Helper()
	if err := os.Remove(filepath.Join(d.local, filepath.FromSlash(rel))); err != nil {
		d.t.Fatal(err)
	}
}

func (d *vdev) sync() SecureSyncReport {
	d.t.Helper()
	rep, err := d.s.SecureSync(context.Background(), d.root.ID, false)
	if err != nil {
		d.t.Fatalf("sync: %v", err)
	}
	if errs := rep.Errors(); len(errs) > 0 {
		d.t.Fatalf("sync errors: %+v", errs)
	}
	return rep
}

func (d *vdev) files() map[string]string {
	out := map[string]string{}
	filepath.WalkDir(d.local, func(p string, de os.DirEntry, err error) error {
		if err == nil && de.Type().IsRegular() {
			rel, _ := filepath.Rel(d.local, p)
			b, _ := os.ReadFile(p)
			out[filepath.ToSlash(rel)] = string(b)
		}
		return nil
	})
	return out
}

func suiteName(m string) string {
	if m == "" {
		return "plain"
	}
	return m
}

func TestSecureSyncTwoDevices(t *testing.T) {
	for _, method := range []string{"", "aesgcm", "gpg"} {
		t.Run(suiteName(method), func(t *testing.T) {
			if method == "gpg" {
				needGPG(t)
			}
			srv, d := newVDevs(t, method, 2)
			a, b := d[0], d[1]
			a.write("notes.md", "hello from A\n")
			a.write("dir/sub/deep.txt", "deep\n")
			if rep := a.sync(); rep.Count("upload") != 2 {
				t.Fatalf("A uploaded %d: %+v", rep.Count("upload"), rep.Actions)
			}
			sfx := map[string]string{"": "", "aesgcm": ".spe", "gpg": ".gpg"}[method]
			raw, ok := srv.Object("b", "vault/notes.md"+sfx)
			if !ok {
				t.Fatalf("object missing; buckets %v", srv.Buckets())
			}
			if method != "" && bytes.Contains(raw, []byte("hello from A")) {
				t.Fatal("plaintext in the bucket")
			}
			if _, ok := srv.Object("b", "vault/.securepail/vault.json"); !ok {
				t.Fatal("vault marker missing")
			}
			if rep := b.sync(); rep.Count("download") != 2 {
				t.Fatalf("B downloaded %d: %+v", rep.Count("download"), rep.Actions)
			}
			if got, _ := b.read("dir/sub/deep.txt"); got != "deep\n" {
				t.Fatalf("B has %q", got)
			}
			// steady state: nothing to do on either side
			for _, x := range []*vdev{a, b} {
				if rep := x.sync(); len(rep.Actions) != 0 || len(rep.Conflicts) != 0 {
					t.Fatalf("second sync not idle: %+v", rep)
				}
			}
			// edit on B, propagate to A
			b.write("notes.md", "edited on B\n")
			b.sync()
			a.sync()
			if got, _ := a.read("notes.md"); got != "edited on B\n" {
				t.Fatalf("A has %q", got)
			}
			// device registry
			if _, ok := srv.Object("b", "vault/.securepail/devices/"+a.mustDevice().ID+".json"); !ok {
				t.Fatal("device file missing")
			}
		})
	}
}

func (d *vdev) mustDevice() Device {
	dev, err := d.s.SecureDevice()
	if err != nil {
		d.t.Fatal(err)
	}
	return dev
}

func TestSecureSyncConflictResolutions(t *testing.T) {
	setup := func(t *testing.T) (*vdev, *vdev) {
		_, d := newVDevs(t, "aesgcm", 2)
		d[0].write("a.txt", "base\n")
		d[0].sync()
		d[1].sync()
		d[0].write("a.txt", "A edit\n")
		d[1].write("a.txt", "B edit longer\n")
		d[0].sync() // A wins the race, uploads
		return d[0], d[1]
	}
	t.Run("detected, nothing lost", func(t *testing.T) {
		_, b := setup(t)
		rep := b.sync()
		if len(rep.Conflicts) != 1 || rep.Conflicts[0].Kind != string(vsync.BothChanged) {
			t.Fatalf("conflicts: %+v", rep.Conflicts)
		}
		if got, _ := b.read("a.txt"); got != "B edit longer\n" {
			t.Fatalf("a conflicting sync touched the local file: %q", got)
		}
	})
	t.Run("overwrite remote", func(t *testing.T) {
		a, b := setup(t)
		b.sync()
		if _, err := b.s.SecureResolve(context.Background(), b.root.ID, "a.txt", vsync.OverwriteRemote); err != nil {
			t.Fatal(err)
		}
		a.sync()
		if got, _ := a.read("a.txt"); got != "B edit longer\n" {
			t.Fatalf("A has %q", got)
		}
	})
	t.Run("overwrite local", func(t *testing.T) {
		_, b := setup(t)
		if _, err := b.s.SecureResolve(context.Background(), b.root.ID, "a.txt", vsync.OverwriteLocal); err != nil {
			t.Fatal(err)
		}
		if got, _ := b.read("a.txt"); got != "A edit\n" {
			t.Fatalf("B has %q", got)
		}
		if rep := b.sync(); len(rep.Actions) != 0 {
			t.Fatalf("not idle after resolving: %+v", rep.Actions)
		}
	})
	t.Run("keep both", func(t *testing.T) {
		a, b := setup(t)
		msg, err := b.s.SecureResolve(context.Background(), b.root.ID, "a.txt", vsync.KeepBoth)
		if err != nil {
			t.Fatal(err)
		}
		files := b.files()
		if files["a.txt"] != "A edit\n" {
			t.Fatalf("B a.txt = %q", files["a.txt"])
		}
		var copyName string
		for n, c := range files {
			if strings.Contains(n, "(conflict") && c == "B edit longer\n" {
				copyName = n
			}
		}
		if copyName == "" {
			t.Fatalf("no conflict copy (%s): %v", msg, files)
		}
		b.sync() // uploads the copy
		a.sync()
		if got, _ := a.read(copyName); got != "B edit longer\n" {
			t.Fatalf("A did not receive the copy: %q", got)
		}
	})
	t.Run("keep newest", func(t *testing.T) {
		_, b := setup(t)
		if _, err := b.s.SecureResolve(context.Background(), b.root.ID, "a.txt", vsync.KeepNewest); err != nil {
			t.Fatal(err)
		}
		if rep := b.sync(); len(rep.Actions) != 0 || len(rep.Conflicts) != 0 {
			t.Fatalf("not idle: %+v", rep)
		}
	})
}

func TestSecureSyncSameContentIsNotAConflict(t *testing.T) {
	_, d := newVDevs(t, "aesgcm", 2) // ciphertext differs, plaintext is the same
	a, b := d[0], d[1]
	a.write("x.txt", "base\n")
	a.sync()
	b.sync()
	a.write("x.txt", "same edit\n")
	b.write("x.txt", "same edit\n")
	a.sync()
	rep := b.sync()
	if len(rep.Conflicts) != 0 || rep.Count("check-same") != 1 {
		t.Fatalf("expected a silent merge: %+v", rep)
	}
	if rep := b.sync(); len(rep.Actions) != 0 {
		t.Fatalf("not idle: %+v", rep.Actions)
	}
}

func TestSecureSyncDeletesTrashAndRestore(t *testing.T) {
	srv, d := newVDevs(t, "aesgcm", 2)
	a, b := d[0], d[1]
	a.write("keep.txt", "k\n")
	a.write("gone.txt", "bye\n")
	a.sync()
	b.sync()
	a.remove("gone.txt")
	if rep := a.sync(); rep.Count("trash-remote") != 1 {
		t.Fatalf("%+v", rep.Actions)
	}
	if _, ok := srv.Object("b", "vault/gone.txt.spe"); ok {
		t.Fatal("deleted object still in place")
	}
	items, err := a.s.SecureTrashList(context.Background(), a.root.ID)
	if err != nil || len(items) != 1 || items[0].Path != "gone.txt" {
		t.Fatalf("trash: %+v %v", items, err)
	}
	if rep := b.sync(); rep.Count("trash-local") != 1 {
		t.Fatalf("B: %+v", rep.Actions)
	}
	if _, ok := b.read("gone.txt"); ok {
		t.Fatal("B still has the file")
	}
	// restore, then both devices get it back
	if err := a.s.SecureTrashRestore(context.Background(), a.root.ID, items[0].Key); err != nil {
		t.Fatal(err)
	}
	a.sync()
	b.sync()
	if got, _ := b.read("gone.txt"); got != "bye\n" {
		t.Fatalf("restored content %q", got)
	}
	if left, _ := a.s.SecureTrashList(context.Background(), a.root.ID); len(left) != 0 {
		t.Fatalf("trash not emptied: %+v", left)
	}
}

func TestSecureSyncDeleteVersusEditConflicts(t *testing.T) {
	_, d := newVDevs(t, "aesgcm", 2)
	a, b := d[0], d[1]
	a.write("f.txt", "v1\n")
	a.sync()
	b.sync()
	a.remove("f.txt")
	b.write("f.txt", "edited by B\n")
	a.sync()
	rep := b.sync()
	if len(rep.Conflicts) != 1 || rep.Conflicts[0].Kind != string(vsync.LocalChangedRemoteDeleted) {
		t.Fatalf("%+v", rep.Conflicts)
	}
	if got, _ := b.read("f.txt"); got != "edited by B\n" {
		t.Fatal("B's edit was lost")
	}
	// Keep both on a deletion conflict keeps the surviving edit.
	if _, err := b.s.SecureResolve(context.Background(), b.root.ID, "f.txt", vsync.KeepBoth); err != nil {
		t.Fatal(err)
	}
	b.sync()
	a.sync()
	if got, _ := a.read("f.txt"); got != "edited by B\n" {
		t.Fatalf("A has %q", got)
	}
}

func TestSecureSyncDryRunChangesNothing(t *testing.T) {
	srv, d := newVDevs(t, "aesgcm", 1)
	d[0].write("a.txt", "x")
	rep, err := d[0].s.SecureSync(context.Background(), d[0].root.ID, true)
	if err != nil || rep.Count("upload") != 1 && len(rep.Actions) != 1 {
		t.Fatalf("%+v %v", rep, err)
	}
	if len(srv.Buckets()) > 0 {
		if _, ok := srv.Object("b", "vault/a.txt.spe"); ok {
			t.Fatal("dry run uploaded")
		}
	}
}

func TestSecureSyncRejectsUnsafeRemoteKeys(t *testing.T) {
	srv, d := newVDevs(t, "", 1)
	srv.PutObject("b", "vault/../escape.txt", []byte("x"), "text/plain", nil)
	srv.PutObject("b", "vault/ok.txt", []byte("fine"), "text/plain", nil)
	rep, err := d[0].s.SecureSync(context.Background(), d[0].root.ID, false)
	if err != nil {
		t.Fatal(err)
	}
	if _, bad := d[0].read("../escape.txt"); bad {
		t.Fatal("wrote outside the root")
	}
	if got, _ := d[0].read("ok.txt"); got != "fine" {
		t.Fatalf("ok.txt = %q (%+v)", got, rep)
	}
}

func TestSecureSyncDownloadDoesNotOverwriteConcurrentEdit(t *testing.T) {
	_, d := newVDevs(t, "", 2)
	a, b := d[0], d[1]
	a.write("f.txt", "v1\n")
	a.sync()
	b.sync()
	a.write("f.txt", "v2 from A\n")
	a.sync()
	// B edits the file after the remote changed but before B syncs: both changed.
	b.write("f.txt", "B's own work\n")
	b.sync()
	if got, _ := b.read("f.txt"); got != "B's own work\n" {
		t.Fatalf("B's edit was overwritten: %q", got)
	}
}

// Three devices, random edits, deletes and sync order. After resolving every
// conflict with "keep both" and syncing until quiet, all devices must hold
// identical files and no sync may report an error. (Overwriting an older
// version by a newer edit is normal, so "no edit lost" is tested by the
// conflict tests, where the two edits are concurrent.)
func TestSecureSyncThreeDeviceSimulation(t *testing.T) {
	for seed := int64(1); seed <= 4; seed++ {
		t.Run(fmt.Sprintf("seed%d", seed), func(t *testing.T) {
			rng := rand.New(rand.NewSource(seed))
			_, d := newVDevs(t, "aesgcm", 3)
			names := []string{"a.txt", "b.txt", "dir/c.txt", "dir/d.txt", "e.txt"}
			written := 0
			ctx := context.Background()
			for step := 0; step < 40; step++ {
				dev := d[rng.Intn(3)]
				name := names[rng.Intn(len(names))]
				switch rng.Intn(5) {
				case 0, 1, 2:
					c := fmt.Sprintf("seed%d step%d %s on %s\n", seed, step, name, dev.mustDevice().ID)
					dev.write(name, c)
					written++
				case 3:
					if _, ok := dev.read(name); ok {
						dev.remove(name)
					}
				case 4:
					rep, err := dev.s.SecureSync(ctx, dev.root.ID, false)
					if err != nil {
						t.Fatal(err)
					}
					if errs := rep.Errors(); len(errs) > 0 {
						t.Fatalf("step %d: %+v", step, errs)
					}
				}
			}
			// settle: keep both on every conflict, sync everyone until nothing moves
			for round := 0; round < 12; round++ {
				moved := false
				for _, dev := range d {
					rep := dev.sync()
					for _, c := range rep.Conflicts {
						if _, err := dev.s.SecureResolve(ctx, dev.root.ID, c.Path, vsync.KeepBoth); err != nil {
							t.Fatalf("resolve %s: %v", c.Path, err)
						}
						moved = true
					}
					if len(rep.Actions) > 0 {
						moved = true
					}
				}
				if !moved {
					break
				}
			}
			ref := d[0].files()
			for i := 1; i < 3; i++ {
				if got := d[i].files(); !sameFiles(ref, got) {
					t.Fatalf("device %d differs from device 0:\n%v\nvs\n%v", i, keys(got), keys(ref))
				}
			}
			t.Logf("seed %d: %d files converged, %d edits", seed, len(ref), written)
		})
	}
}

func sameFiles(a, b map[string]string) bool {
	if len(a) != len(b) {
		return false
	}
	for k, v := range a {
		if b[k] != v {
			return false
		}
	}
	return true
}

func keys(m map[string]string) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

func TestSecurePreviewAndCaps(t *testing.T) {
	_, d := newVDevs(t, "aesgcm", 1)
	a := d[0]
	a.write("n.md", "# title\nbody\n")
	a.write("bin.dat", string([]byte{0xff, 0xfe, 0x00, 0x01}))
	a.write("big.txt", strings.Repeat("x", 3000))
	a.sync()
	ctx := context.Background()
	p, err := a.s.SecurePreview(ctx, a.root.ID, "n.md", PreviewCaps{})
	if err != nil || p.Kind != PreviewText || string(p.Data) != "# title\nbody\n" {
		t.Fatalf("%+v %v", p, err)
	}
	p, err = a.s.SecurePreview(ctx, a.root.ID, "bin.dat", PreviewCaps{})
	if err != nil || p.Kind != PreviewHex {
		t.Fatalf("%+v %v", p, err)
	}
	p, err = a.s.SecurePreview(ctx, a.root.ID, "big.txt", PreviewCaps{TextBytes: 1000})
	if err != nil || p.Kind != PreviewTooLarge {
		t.Fatalf("size cap not enforced: %+v %v", p, err)
	}
	if _, err := a.s.SecurePreview(ctx, a.root.ID, "missing.txt", PreviewCaps{}); err == nil {
		t.Fatal("preview of a missing file succeeded")
	}
}

func TestSecureEditSaveBack(t *testing.T) {
	_, d := newVDevs(t, "aesgcm", 2)
	a, b := d[0], d[1]
	a.write("doc.md", "v1\n")
	a.sync()
	ctx := context.Background()
	ed, err := a.s.SecureEditOpen(ctx, a.root.ID, "doc.md")
	if err != nil {
		t.Fatal(err)
	}
	if ch, _ := a.s.SecureEditChanged(ed.ID); ch {
		t.Fatal("unchanged edit reported as changed")
	}
	if err := os.WriteFile(ed.File, []byte("v2 edited\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if ch, _ := a.s.SecureEditChanged(ed.ID); !ch {
		t.Fatal("change not detected")
	}
	if err := a.s.SecureEditSave(ctx, ed.ID, SaveStrict); err != nil {
		t.Fatal(err)
	}
	if got, _ := a.read("doc.md"); got != "v2 edited\n" {
		t.Fatalf("local copy not updated: %q", got)
	}
	b.sync()
	if got, _ := b.read("doc.md"); got != "v2 edited\n" {
		t.Fatalf("B has %q", got)
	}
	// a second edit loses the race against B
	os.WriteFile(ed.File, []byte("v3 from A\n"), 0o600)
	b.write("doc.md", "v3 from B\n")
	b.sync()
	err = a.s.SecureEditSave(ctx, ed.ID, SaveStrict)
	if err == nil || KindOf(err) != ErrConflict {
		t.Fatalf("expected a conflict, got %v", err)
	}
	if err := a.s.SecureEditSave(ctx, ed.ID, SaveKeepBoth); err != nil {
		t.Fatal(err)
	}
	a.sync()
	files := a.files()
	if files["doc.md"] != "v3 from B\n" {
		t.Fatalf("remote version lost: %v", files)
	}
	found := false
	for n, c := range files {
		if strings.Contains(n, "(conflict") && c == "v3 from A\n" {
			found = true
		}
	}
	if !found {
		t.Fatalf("edit not kept as a conflict copy: %v", keys(files))
	}
	dir := filepath.Dir(ed.File)
	if err := a.s.SecureEditClose(ed.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(dir); err == nil {
		t.Fatal("plaintext folder not removed")
	}
}

// A device that listed the remote, then lost the race to another device, must
// re-plan the path (412) instead of overwriting the newer version.
func TestSecureSyncLostRaceReplans(t *testing.T) {
	_, d := newVDevs(t, "aesgcm", 2)
	a, b := d[0], d[1]
	a.write("r.txt", "v1\n")
	a.sync()
	b.sync()
	ctx := context.Background()
	run, err := b.s.newSecureRun(ctx, "test", b.root)
	if err != nil {
		t.Fatal(err)
	}
	stale, err := run.listRemote(ctx) // B's view of the remote: v1
	if err != nil {
		t.Fatal(err)
	}
	local, _ := run.scanLocal()
	b.write("r.txt", "B edit\n")
	local, _ = run.scanLocal()
	a.write("r.txt", "A edit, uploaded first\n")
	a.sync()
	run.syncPath(ctx, "r.txt", stale["r.txt"], local["r.txt"])
	if errs := run.rep.Errors(); len(errs) != 0 {
		t.Fatalf("%+v", errs)
	}
	// B's stale PutObject was refused; the re-plan found both sides changed.
	if len(run.rep.Conflicts) != 1 {
		t.Fatalf("expected a conflict after the lost race: %+v", run.rep)
	}
	got, _ := a.s.SecurePreview(ctx, a.root.ID, "r.txt", PreviewCaps{})
	if string(got.Data) != "A edit, uploaded first\n" {
		t.Fatalf("the remote version was overwritten: %q", got.Data)
	}
}

// Switching a root from plain to encrypted: unchanged files stay as they are,
// a changed file moves to the encrypted key and the old object goes to the trash.
func TestSecureSyncSuiteChange(t *testing.T) {
	srv, d := newVDevs(t, "", 1)
	a := d[0]
	a.write("old.txt", "v1\n")
	a.write("same.txt", "same\n")
	a.sync()
	key, _ := seclayer.GenerateKey()
	if err := a.s.SetSecret("newkey", key); err != nil {
		t.Fatal(err)
	}
	root := a.root
	root.Method, root.KeyRef = "aesgcm", "newkey"
	if _, err := a.s.SaveSecureRoot(root); err != nil {
		t.Fatal(err)
	}
	a.root = root
	if rep := a.sync(); len(rep.Actions) != 0 {
		t.Fatalf("unchanged files must not be re-uploaded: %+v", rep.Actions)
	}
	a.write("old.txt", "v2\n")
	a.sync()
	if _, ok := srv.Object("b", "vault/old.txt.spe"); !ok {
		t.Fatal("changed file not stored encrypted")
	}
	if _, ok := srv.Object("b", "vault/old.txt"); ok {
		t.Fatal("the plain object is still in place")
	}
	items, _ := a.s.SecureTrashList(context.Background(), a.root.ID)
	if len(items) != 1 || items[0].Path != "old.txt" {
		t.Fatalf("old object not in the trash: %+v", items)
	}
	if rep := a.sync(); len(rep.Actions) != 0 || len(rep.Conflicts) != 0 {
		t.Fatalf("not idle afterwards: %+v", rep)
	}
}
