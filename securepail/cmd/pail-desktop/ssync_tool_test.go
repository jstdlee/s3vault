package main

import (
	"testing"

	core "github.com/jstdlee/securePail/internal/app"
)

func TestSecureSyncToolEmptyAndWithConflicts(t *testing.T) {
	h := newHarness(t, "light")
	h.openToolView("ssync")
	h.mustHave("No secure sync folders yet")

	if _, err := h.a.svc.SaveSecureRoot(core.SecureRoot{Name: "docs", AccountID: "acct", Bucket: "b", Local: t.TempDir()}); err != nil {
		t.Fatal(err)
	}
	h.a.ssyncEnter()
	h.tt.Frame()
	h.mustHave("Sync now", "Preview changes", "Conflicts", "No conflicts.", "Remote trash")

	st := &h.a.tl.ssync
	st.rep = &core.SecureSyncReport{Conflicts: []core.SecureConflict{
		{Path: "notes/a.md", Kind: "both-changed"},
		{Path: "b.txt", Kind: "local-changed-remote-deleted"},
	}}
	h.tt.Frame()
	h.mustHave("notes/a.md", "Changed on both sides", "Changed here, deleted there", "Keep both", "Use mine", "Use remote", "Newest")

	h.setLocale("zh-Hans")
	h.mustHave("安全同步", "立即同步", "冲突", "都保留", "用本地的")
	h.setLocale("en")
}

func TestSecureSyncSummaryWording(t *testing.T) {
	rep := core.SecureSyncReport{Actions: []core.SecureAction{{Op: "upload"}, {Op: "upload"}, {Op: "download"}, {Op: "trash-remote"}, {Op: "upload", Err: "x"}},
		Conflicts: []core.SecureConflict{{}}}
	got := ssyncSummary(rep)
	want := "2 uploaded · 1 downloaded · 1 deleted · 1 conflicts · 1 errors"
	if got != want {
		t.Fatalf("got %q want %q", got, want)
	}
}
