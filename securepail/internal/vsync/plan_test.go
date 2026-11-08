package vsync

import (
	"path/filepath"
	"testing"
	"time"
)

func TestDecideTable(t *testing.T) {
	has := func(changed bool) Local { return Local{Exists: true, Changed: changed} }
	none := Local{}
	rem := func(etag string) Remote { return Remote{Exists: true, ETag: etag} }
	base := Base{Exists: true, ETag: "e1"}
	for _, tc := range []struct {
		name string
		l    Local
		r    Remote
		b    Base
		want Step
	}{
		{"nothing anywhere", none, Remote{}, Base{}, Step{Op: OpNone}},
		{"new local", has(false), Remote{}, Base{}, Step{Op: OpUpload, IfNoneMatch: true}},
		{"new remote", none, rem("e1"), Base{}, Step{Op: OpDownload}},
		{"new on both", has(false), rem("e1"), Base{}, Step{Op: OpCheckSame}},
		{"in sync", has(false), rem("e1"), base, Step{Op: OpNone}},
		{"local changed", has(true), rem("e1"), base, Step{Op: OpUpload, IfMatch: "e1"}},
		{"remote changed", has(false), rem("e2"), base, Step{Op: OpDownload}},
		{"both changed", has(true), rem("e2"), base, Step{Op: OpCheckSame}},
		{"deleted locally, remote same", none, rem("e1"), base, Step{Op: OpTrashRemote}},
		{"deleted locally, remote changed", none, rem("e2"), base, Step{Op: OpConflict, Conflict: LocalDeletedRemoteChanged}},
		{"deleted remotely, local same", has(false), Remote{}, base, Step{Op: OpTrashLocal}},
		{"deleted remotely, local changed", has(true), Remote{}, base, Step{Op: OpConflict, Conflict: LocalChangedRemoteDeleted}},
		{"gone on both", none, Remote{}, base, Step{Op: OpForget}},
	} {
		if got := Decide(tc.l, tc.r, tc.b); got != tc.want {
			t.Errorf("%s: got %+v, want %+v", tc.name, got, tc.want)
		}
	}
}

func TestConflictName(t *testing.T) {
	at := time.Date(2026, 11, 8, 23, 0, 0, 0, time.FixedZone("x", 3600*5))
	for in, want := range map[string]string{
		"notes.md":       "notes (conflict laptop 2026-11-08).md",
		"a/b/report.tar": "a/b/report (conflict laptop 2026-11-08).tar",
		"noext":          "noext (conflict laptop 2026-11-08)",
		".env":           ".env (conflict laptop 2026-11-08)",
	} {
		if got := ConflictName(in, "laptop", at); got != want {
			t.Errorf("%q: got %q want %q", in, got, want)
		}
	}
	if got := ConflictName("x.txt", "my/dev:1", at); got != "x (conflict my-dev-1 2026-11-08).txt" {
		t.Errorf("device sanitising: %q", got)
	}
}

func TestNewest(t *testing.T) {
	a, b := time.Unix(100, 0), time.Unix(200, 0)
	if Newest(a, b) != OverwriteLocal || Newest(b, a) != OverwriteRemote || Newest(a, a) != OverwriteRemote {
		t.Fatal("Newest")
	}
}

func TestIndexRoundTripAndCorruption(t *testing.T) {
	p := filepath.Join(t.TempDir(), "x", "idx.json")
	ix, err := LoadIndex(p)
	if err != nil {
		t.Fatal(err)
	}
	ix.Set("a.txt", Entry{ETag: "e", Hash: "h", Size: 3})
	if err := ix.Save(); err != nil {
		t.Fatal(err)
	}
	ix2, err := LoadIndex(p)
	if err != nil {
		t.Fatal(err)
	}
	if e, ok := ix2.Get("a.txt"); !ok || e.ETag != "e" {
		t.Fatalf("%+v %v", e, ok)
	}
	ix2.Delete("a.txt")
	if len(ix2.Paths()) != 0 {
		t.Fatal("not deleted")
	}
	if err := writeFile(p, "{not json"); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadIndex(p); err == nil {
		t.Fatal("damaged index accepted")
	}
}
