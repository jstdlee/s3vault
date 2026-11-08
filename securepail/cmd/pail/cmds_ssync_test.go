package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestSSyncEndToEnd(t *testing.T) {
	h := newHarness(t)
	h.want(h.run("secure", "keygen", "vk"), 0)
	local := t.TempDir()
	h.want(h.run("ssync", "root", "add", "docs", local, "s3://bkt/vault/", "--suite", "aesgcm", "--key", "vk", "--plain", "*.txt"), 0)
	if r := h.want(h.run("ssync", "root", "ls"), 0); !strings.Contains(r.out, "docs") || !strings.Contains(r.out, "aesgcm") {
		t.Fatalf("ls: %s", r.out)
	}
	os.WriteFile(filepath.Join(local, "secret.md"), []byte("top secret\n"), 0o644)
	os.WriteFile(filepath.Join(local, "plain.txt"), []byte("public\n"), 0o644)

	r := h.want(h.run("ssync", "run", "docs", "--dry-run"), 0)
	if !strings.Contains(r.out, "upload\tsecret.md") {
		t.Fatalf("dry run: %s", r.out)
	}
	if _, ok := h.srv.Object("bkt", "vault/secret.md.spe"); ok {
		t.Fatal("dry run uploaded")
	}
	h.want(h.run("ssync", "run", "docs"), 0)
	raw, ok := h.srv.Object("bkt", "vault/secret.md.spe")
	if !ok || strings.Contains(string(raw), "top secret") {
		t.Fatalf("encrypted object missing or readable (%v)", ok)
	}
	if b, ok := h.srv.Object("bkt", "vault/plain.txt"); !ok || string(b) != "public\n" {
		t.Fatal("plain glob not honoured")
	}
	if r := h.want(h.run("ssync", "preview", "docs", "secret.md"), 0); r.out != "top secret\n" {
		t.Fatalf("preview: %q", r.out)
	}
	// delete locally -> trash -> restore
	os.Remove(filepath.Join(local, "secret.md"))
	h.want(h.run("ssync", "run", "docs"), 0)
	tr := h.want(h.run("ssync", "trash", "docs", "ls"), 0)
	fields := strings.Split(strings.TrimSpace(tr.out), "\t")
	if len(fields) != 4 || fields[1] != "secret.md" {
		t.Fatalf("trash ls: %q", tr.out)
	}
	h.want(h.run("ssync", "trash", "docs", "restore", fields[3]), 0)
	h.want(h.run("ssync", "run", "docs"), 0)
	if b, _ := os.ReadFile(filepath.Join(local, "secret.md")); string(b) != "top secret\n" {
		t.Fatalf("restored file: %q", b)
	}
	h.want(h.run("ssync", "conflicts", "docs"), 0)
	h.want(h.run("ssync", "root", "rm", "docs"), 0)
}
