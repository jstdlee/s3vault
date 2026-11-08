package main

import (
	"context"
	"strconv"
	"time"

	"github.com/egoist/mygo/ui"

	"github.com/jstdlee/securePail/cmd/pail-desktop/icons"
	"github.com/jstdlee/securePail/cmd/pail-desktop/locales"
	core "github.com/jstdlee/securePail/internal/app"
	"github.com/jstdlee/securePail/internal/vsync"
)

// Secure sync tool: run a two-way sync of a root, settle conflicts and restore
// from the remote trash. Roots are created with `pail ssync root add`.

type ssyncState struct {
	roots []core.SecureRoot
	sel   int
	busy  bool
	rep   *core.SecureSyncReport
	msg   string
	err   string
	trash []core.SecureTrashItem
	list  ui.ListState
	tlist ui.ListState
	gen   int
}

func (a *app) ssyncEnter() {
	st := &a.tl.ssync
	roots, err := a.svc.SecureRoots()
	*st = ssyncState{roots: roots, sel: 0}
	if err != nil {
		st.err = err.Error()
	}
}

func (st *ssyncState) root() (core.SecureRoot, bool) {
	if st.sel < 0 || st.sel >= len(st.roots) {
		return core.SecureRoot{}, false
	}
	return st.roots[st.sel], true
}

// ssyncRun runs fn off the UI thread and shows its outcome.
func (a *app) ssyncRun(d time.Duration, fn func(ctx context.Context, root core.SecureRoot) (rep *core.SecureSyncReport, msg string, err error)) {
	st := &a.tl.ssync
	root, ok := st.root()
	if !ok || st.busy {
		return
	}
	st.busy, st.err, st.msg = true, "", ""
	st.gen++
	gen := st.gen
	ctx, cancel := a.timeout(d)
	go func() {
		defer cancel()
		rep, msg, err := fn(ctx, root)
		a.post(func() {
			s := &a.tl.ssync
			if gen != s.gen {
				return
			}
			s.busy = false
			if err != nil {
				s.err = err.Error()
			}
			if rep != nil {
				s.rep = rep
			}
			s.msg = msg
		})
	}()
}

func (a *app) ssyncSync(dry bool) {
	a.ssyncRun(30*time.Minute, func(ctx context.Context, r core.SecureRoot) (*core.SecureSyncReport, string, error) {
		rep, err := a.svc.SecureSync(ctx, r.ID, dry)
		return &rep, "", err
	})
}

func (a *app) ssyncResolve(path string, res vsync.Resolution) {
	a.ssyncRun(10*time.Minute, func(ctx context.Context, r core.SecureRoot) (*core.SecureSyncReport, string, error) {
		msg, err := a.svc.SecureResolve(ctx, r.ID, path, res)
		if err != nil {
			return nil, "", err
		}
		rep, err := a.svc.SecureSync(ctx, r.ID, true) // refresh the conflict list
		return &rep, msg, err
	})
}

func (a *app) ssyncLoadTrash() {
	st := &a.tl.ssync
	root, ok := st.root()
	if !ok || st.busy {
		return
	}
	st.busy = true
	ctx, cancel := a.timeout(time.Minute)
	go func() {
		defer cancel()
		items, err := a.svc.SecureTrashList(ctx, root.ID)
		a.post(func() {
			s := &a.tl.ssync
			s.busy = false
			if err != nil {
				s.err = err.Error()
				return
			}
			s.trash = items
		})
	}()
}

func (a *app) ssyncRestore(key string) {
	st := &a.tl.ssync
	root, ok := st.root()
	if !ok || st.busy {
		return
	}
	st.busy = true
	ctx, cancel := a.timeout(time.Minute)
	go func() {
		defer cancel()
		err := a.svc.SecureTrashRestore(ctx, root.ID, key)
		a.post(func() {
			s := &a.tl.ssync
			s.busy = false
			if err != nil {
				s.err = err.Error()
				return
			}
			s.msg = locales.SsyncRestored()
			s.trash = nil
			a.ssyncLoadTrash()
		})
	}()
}

func ssyncSummary(rep core.SecureSyncReport) string {
	return locales.SsyncSummary(
		strconv.Itoa(rep.Count("upload")), strconv.Itoa(rep.Count("download")),
		strconv.Itoa(rep.Count("trash-remote")+rep.Count("trash-local")),
		strconv.Itoa(len(rep.Conflicts)), strconv.Itoa(len(rep.Errors())))
}

func (a *app) ssyncView(c *ui.Context) {
	k := tk(c)
	st := &a.tl.ssync
	if len(st.roots) == 0 {
		emptyBlock(c, "refresh-ccw", locales.SsyncNoRoots(), locales.SsyncNoRootsHint(), 0)
		return
	}
	ui.Column(c).Grow(1).MinHeight(0).Children(func() {
		ui.Row(c).Padding(12, 16, 8, 16).Gap(8).AlignItems(ui.Center).Shrink(0).Children(func() {
			opts := make([]choice, len(st.roots))
			for i, r := range st.roots {
				opts[i] = choice{strconv.Itoa(i), r.Name}
			}
			sel := strconv.Itoa(st.sel)
			if selectBox(c, locales.SsyncRoot(), &sel, opts, 220) {
				if i, err := strconv.Atoi(sel); err == nil && i != st.sel {
					st.sel, st.rep, st.msg, st.err, st.trash = i, nil, "", "", nil
				}
			}
			if r, ok := st.root(); ok {
				mono(ui.Text(c, r.Local).FontSize(sizeSecondary).TextColor(k.TextMuted).SingleLine().Shrink(1).MinWidth(0))
			}
			ui.Spacer(c)
			if secondaryButton(c, locales.SsyncPreview(), st.busy).Clicked() {
				a.ssyncSync(true)
			}
			if primaryButton(c, locales.SsyncSyncNow(), st.busy).Clicked() {
				a.ssyncSync(false)
			}
		})
		switch {
		case st.busy:
			ui.Text(c, locales.SsyncWorking()).FontSize(sizeSecondary).TextColor(k.TextMuted).Padding(0, 16)
		case st.err != "":
			ui.Text(c, st.err).FontSize(sizeSecondary).TextColor(k.Danger).Padding(0, 16)
		case st.msg != "":
			ui.Text(c, st.msg).FontSize(sizeSecondary).TextColor(k.Text).Padding(0, 16)
		case st.rep != nil:
			ui.Text(c, ssyncSummary(*st.rep)).FontSize(sizeSecondary).TextColor(k.TextMuted).Padding(0, 16)
		}
		ruleSection(c, locales.SsyncConflicts(), "")
		a.ssyncConflicts(c)
		ruleSection(c, locales.SsyncTrash(), "")
		a.ssyncTrashList(c)
	})
}

func (a *app) ssyncConflicts(c *ui.Context) {
	st := &a.tl.ssync
	if st.rep == nil || len(st.rep.Conflicts) == 0 {
		ui.Text(c, locales.SsyncNoConflicts()).FontSize(sizeSecondary).Padding(0, 16)
		return
	}
	list := st.rep.Conflicts
	cols := []ui.TableColumn{
		{Title: locales.SsyncPath(), ID: "path", MinWidth: 180},
		{Title: locales.SsyncWhy(), ID: "why", Width: 220},
		{Title: "", ID: "act", Width: 360, Fixed: true},
	}
	st.list.Key = func(i int) any { return list[i].Path }
	var path string
	var res vsync.Resolution
	toolTable(c, &st.list, cols, len(list), func(row, col int) {
		x := list[row]
		switch col {
		case 0:
			mono(ui.Text(c.Key("p"), x.Path).FontSize(sizeSecondary).SingleLine())
		case 1:
			ui.Text(c.Key("w"), ssyncKind(x.Kind)).FontSize(sizeSecondary).SingleLine()
		case 2:
			ui.Row(c.Key("a")).Gap(4).Children(func() {
				for _, b := range []struct {
					id    string
					label string
					r     vsync.Resolution
				}{
					{"kb", locales.SsyncKeepBoth(), vsync.KeepBoth},
					{"lo", locales.SsyncUseMine(), vsync.OverwriteRemote},
					{"re", locales.SsyncUseRemote(), vsync.OverwriteLocal},
					{"nw", locales.SsyncNewest(), vsync.KeepNewest},
				} {
					if ghostButton(c.Key(b.id), nil, b.label, "", st.busy).Clicked() {
						path, res = x.Path, b.r
					}
				}
			})
		}
	}).Height(float32(34*len(list) + 34)).Label(locales.SsyncConflicts())
	if path != "" {
		a.ssyncResolve(path, res)
	}
}

func ssyncKind(kind string) string {
	switch vsync.ConflictKind(kind) {
	case vsync.BothNew:
		return locales.SsyncKindBothNew()
	case vsync.BothChanged:
		return locales.SsyncKindBothChanged()
	case vsync.LocalDeletedRemoteChanged:
		return locales.SsyncKindLocalDeleted()
	case vsync.LocalChangedRemoteDeleted:
		return locales.SsyncKindRemoteDeleted()
	}
	return kind
}

func (a *app) ssyncTrashList(c *ui.Context) {
	st := &a.tl.ssync
	ui.Row(c).Padding(0, 16, 8, 16).Gap(8).AlignItems(ui.Center).Shrink(0).Children(func() {
		if secondaryButton(c, locales.SsyncShowTrash(), st.busy).Clicked() {
			a.ssyncLoadTrash()
		}
	})
	if len(st.trash) == 0 {
		return
	}
	items := st.trash
	cols := []ui.TableColumn{
		{Title: locales.SsyncPath(), ID: "path", MinWidth: 180},
		{Title: locales.SsyncDeleted(), ID: "when", Width: 180},
		{Title: "", ID: "act", Width: 110, Fixed: true},
	}
	st.tlist.Key = func(i int) any { return items[i].Key }
	restore := ""
	toolTable(c, &st.tlist, cols, len(items), func(row, col int) {
		it := items[row]
		switch col {
		case 0:
			mono(ui.Text(c.Key("p"), it.Path).FontSize(sizeSecondary).SingleLine())
		case 1:
			ui.Text(c.Key("d"), it.Deleted.Local().Format("2006-01-02 15:04")).FontSize(sizeSecondary).SingleLine()
		case 2:
			if ghostButton(c.Key("r"), icons.Get("rotate-ccw"), locales.SsyncRestore(), "", st.busy).Clicked() {
				restore = it.Key
			}
		}
	}).Height(float32(34*len(items) + 34)).Label(locales.SsyncTrash())
	if restore != "" {
		a.ssyncRestore(restore)
	}
}
