package main

import (
	"testing"

	"github.com/jstdlee/securePail/internal/readiness"
	"github.com/jstdlee/securePail/internal/rules"
)

// The form must not drop the secure layer when a rule is edited and saved.
func TestRuleFormKeepsSecureLayer(t *testing.T) {
	in := rules.UploadRule{Name: "s", KeyPattern: "docs/*", Secure: &rules.Secure{Method: "gpg", KeyRef: "vk"}}
	f := formFromRule(in)
	out := f.rule(false)
	if out.Secure == nil || *out.Secure != *in.Secure {
		t.Fatalf("secure layer lost: %+v", out.Secure)
	}
	if got := ruleSummary(out); got != "GPG" {
		t.Errorf("summary = %q", got)
	}
	pf := formFromRule(rules.UploadRule{Name: "p", Secure: &rules.Secure{Method: "aesgcm", KeyRef: "vk"}})
	if r := pf.rule(false); r.Secure == nil || r.Secure.Method != "aesgcm" || ruleSummary(r) != "AES-256-GCM" {
		t.Fatalf("portable layer lost or mislabelled: %+v", r.Secure)
	}
	none := formFromRule(rules.UploadRule{Name: "n"})
	if r := none.rule(false); r.Secure != nil {
		t.Errorf("unexpected secure layer: %+v", r.Secure)
	}
}

func TestReadyLinesOnlyProblems(t *testing.T) {
	rep := readiness.Report{Items: []readiness.Item{
		{ID: "gpg", Name: "GnuPG (gpg)", Status: readiness.OK, Detail: "found 2.4.4"},
		{ID: "keyring", Name: "OS key store", Status: readiness.Fail, Detail: "cannot store a secret", Hint: "unlock it"},
	}}
	got := readyLines(rep)
	if len(got) != 1 || got[0] == "" {
		t.Fatalf("lines = %q", got)
	}
}
