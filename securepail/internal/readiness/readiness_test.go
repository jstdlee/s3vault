package readiness

import (
	"context"
	"errors"
	"io"
	"os/exec"
	"strings"
	"testing"

	"github.com/jstdlee/securePail/internal/seclayer"
)

type memKR map[string]string

func (m memKR) Set(k, v string) error { m[k] = v; return nil }
func (m memKR) Get(k string) (string, error) {
	if v, ok := m[k]; ok {
		return v, nil
	}
	return "", errors.New("missing")
}
func (m memKR) Delete(k string) error { delete(m, k); return nil }

type brokenKR struct{ memKR }

func (brokenKR) Set(string, string) error { return errors.New("no secret service") }

func byID(r Report, id string) Item {
	for _, it := range r.Items {
		if it.ID == id {
			return it
		}
	}
	return Item{}
}

func TestMissingGPGRequiredVsOptional(t *testing.T) {
	none := func(string) (string, error) { return "", errors.New("nope") }
	for _, need := range []bool{false, true} {
		r := Check(context.Background(), Options{NeedGPG: need, LookPath: none, SpoolDir: t.TempDir()})
		g := byID(r, IDGPG)
		want := Warn
		if need {
			want = Fail
		}
		if g.Status != want || g.Hint == "" {
			t.Errorf("need=%v: gpg item %+v", need, g)
		}
		if r.Ready == need {
			t.Errorf("need=%v: Ready=%v", need, r.Ready)
		}
		if byID(r, IDGPGTest).ID == "" || byID(r, IDAgent).ID == "" {
			t.Error("dependent checks must still be listed")
		}
	}
}

func TestOldGPG(t *testing.T) {
	look := func(n string) (string, error) { return "/bin/" + n, nil }
	run := func(_ context.Context, _ string, _ []string, _ io.Reader, out io.Writer) (string, error) {
		out.Write([]byte("gpg (GnuPG) 2.0.30\n"))
		return "", nil
	}
	r := Check(context.Background(), Options{NeedGPG: true, LookPath: look, Run: run, SpoolDir: t.TempDir()})
	if g := byID(r, IDGPG); g.Status != Fail || !strings.Contains(g.Detail, "too old") || r.Ready {
		t.Fatalf("%+v ready=%v", g, r.Ready)
	}
}

func TestKeyringProbe(t *testing.T) {
	none := func(string) (string, error) { return "", errors.New("nope") }
	good := memKR{}
	r := Check(context.Background(), Options{LookPath: none, Keyring: good, SpoolDir: t.TempDir()})
	if byID(r, IDKeyring).Status != OK || len(good) != 0 {
		t.Fatalf("keyring %+v left=%v", byID(r, IDKeyring), good)
	}
	r = Check(context.Background(), Options{LookPath: none, Keyring: brokenKR{memKR{}}, SpoolDir: t.TempDir()})
	if byID(r, IDKeyring).Status != Fail || r.Ready {
		t.Fatalf("broken keyring must block: %+v", byID(r, IDKeyring))
	}
}

func TestSpoolDirNotWritable(t *testing.T) {
	r := Check(context.Background(), Options{LookPath: func(string) (string, error) { return "", errors.New("x") }, SpoolDir: "/nonexistent/dir"})
	if byID(r, IDSpoolDir).Status != Fail || r.Ready {
		t.Fatalf("%+v", byID(r, IDSpoolDir))
	}
}

func TestRealSystem(t *testing.T) {
	if _, err := exec.LookPath("gpg"); err != nil {
		t.Skip("no gpg")
	}
	t.Setenv("GNUPGHOME", t.TempDir())
	r := Check(context.Background(), Options{NeedGPG: true, Keyring: memKR{}, SpoolDir: t.TempDir()})
	for _, id := range []string{IDGPG, IDGPGTest, IDKeyring, IDSpoolDir} {
		if it := byID(r, id); it.Status != OK {
			t.Errorf("%s: %+v", id, it)
		}
	}
	if !r.Ready || !strings.Contains(r.Render(), "Ready.") {
		t.Fatal(r.Render())
	}
}

func TestSelfTestDetectsBrokenGPG(t *testing.T) {
	look := func(n string) (string, error) { return "/bin/" + n, nil }
	run := func(_ context.Context, _ string, args []string, _ io.Reader, out io.Writer) (string, error) {
		if len(args) == 1 && args[0] == "--version" {
			out.Write([]byte("gpg (GnuPG) 2.4.4\n"))
			return "", nil
		}
		return "gpg: problem with the agent: Forbidden\n", errors.New("exit 2")
	}
	r := Check(context.Background(), Options{NeedGPG: true, LookPath: look, Run: run, SpoolDir: t.TempDir()})
	st := byID(r, IDGPGTest)
	if st.Status != Fail || !strings.Contains(st.Hint, "loopback") || r.Ready {
		t.Fatalf("%+v", st)
	}
	_ = seclayer.ErrNoGPG
}
