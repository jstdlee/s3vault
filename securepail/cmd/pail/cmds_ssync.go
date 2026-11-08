package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/jstdlee/securePail/internal/app"
	"github.com/jstdlee/securePail/internal/vsync"
)

const ssyncSynopsis = `ssync root ls
ssync root add NAME LOCAL s3://bucket/prefix/ [--suite aesgcm|gpg] [--key REF] [--plain GLOB] [--exclude GLOB] [--trash-days N]
ssync root rm NAME
ssync run NAME [--dry-run]
ssync watch NAME [--interval 60s]
ssync conflicts NAME
ssync resolve NAME PATH keep-both|overwrite-remote|overwrite-local|keep-newest|skip
ssync trash NAME ls | restore KEY | purge [--days N]
ssync edit NAME PATH [--editor CMD]
ssync preview NAME PATH`

func setupSSync(c *cli, fs *flag.FlagSet) runner {
	suite := fs.String("suite", "", "root add: encryption suite (aesgcm or gpg); empty keeps files plain")
	key := fs.String("key", "", "root add: key reference (see pail secure keygen)")
	trashDays := fs.Int("trash-days", 0, "root add: days the remote trash is kept (default 30)")
	var plain, exclude multiFlag
	fs.Var(&plain, "plain", "root add: glob of files stored unencrypted (repeatable)")
	fs.Var(&exclude, "exclude", "root add: glob of files that are never synchronised (repeatable)")
	dry := fs.Bool("dry-run", false, "run: show what would happen, change nothing")
	interval := fs.Duration("interval", time.Minute, "watch: time between syncs")
	days := fs.Int("days", 0, "trash purge: delete items older than this many days (default: the root's setting)")
	editor := fs.String("editor", "", "edit: editor command (default $VISUAL, then $EDITOR)")

	return func(ctx context.Context, pos []string) error {
		if len(pos) == 0 {
			return usagef("usage:\n%s", ssyncSynopsis)
		}
		switch pos[0] {
		case "root":
			return c.ssyncRoot(pos[1:], *suite, *key, *trashDays, plain, exclude)
		case "run":
			if len(pos) != 2 {
				return usagef("ssync run takes NAME")
			}
			rep, err := c.svc.SecureSync(ctx, pos[1], *dry)
			c.printSecureReport(rep)
			if err != nil {
				return err
			}
			if n := len(rep.Errors()); n > 0 {
				return &exitErr{exitPartial, fmt.Sprintf("%d path(s) failed", n)}
			}
			if len(rep.Conflicts) > 0 {
				return &exitErr{exitPartial, fmt.Sprintf("%d conflict(s): run pail ssync conflicts %s", len(rep.Conflicts), pos[1])}
			}
			return nil
		case "watch":
			if len(pos) != 2 {
				return usagef("ssync watch takes NAME")
			}
			return c.svc.SecureWatch(ctx, pos[1], *interval, func(rep app.SecureSyncReport, err error) {
				if err != nil {
					c.infof("sync failed: %v", err)
					return
				}
				if len(rep.Actions) > 0 || len(rep.Conflicts) > 0 {
					c.printSecureReport(rep)
				}
			})
		case "conflicts":
			if len(pos) != 2 {
				return usagef("ssync conflicts takes NAME")
			}
			rep, err := c.svc.SecureSync(ctx, pos[1], true)
			if err != nil {
				return err
			}
			c.printConflicts(rep.Conflicts)
			if len(rep.Conflicts) > 0 {
				return &exitErr{exitPartial, fmt.Sprintf("%d conflict(s)", len(rep.Conflicts))}
			}
			return nil
		case "resolve":
			if len(pos) != 4 {
				return usagef("ssync resolve takes NAME PATH and a resolution")
			}
			res := vsync.Resolution(pos[3])
			if !res.Valid() {
				return usagef("resolution must be keep-both, overwrite-remote, overwrite-local, keep-newest or skip")
			}
			msg, err := c.svc.SecureResolve(ctx, pos[1], pos[2], res)
			if err != nil {
				return err
			}
			c.infof("%s", msg)
			return nil
		case "trash":
			return c.ssyncTrash(ctx, pos[1:], *days)
		case "edit":
			if len(pos) != 3 {
				return usagef("ssync edit takes NAME PATH")
			}
			return c.ssyncEdit(ctx, pos[1], pos[2], *editor)
		case "preview":
			if len(pos) != 3 {
				return usagef("ssync preview takes NAME PATH")
			}
			p, err := c.svc.SecurePreview(ctx, pos[1], pos[2], app.PreviewCaps{})
			if err != nil {
				return err
			}
			switch p.Kind {
			case app.PreviewTooLarge:
				return &exitErr{exitFailure, p.Reason}
			case app.PreviewImage:
				fmt.Fprintf(c.io.Stdout, "image %dx%d, %d bytes (use pail cp to save it)\n", p.Width, p.Height, len(p.Data))
			case app.PreviewHex:
				fmt.Fprintf(c.io.Stdout, "binary data, first %d bytes:\n%s", len(p.Data), hexDump(p.Data))
			default:
				c.io.Stdout.Write(p.Data)
			}
			return nil
		}
		return usagef("unknown ssync command %q", pos[0])
	}
}

func hexDump(b []byte) string {
	var sb strings.Builder
	for i := 0; i < len(b); i += 16 {
		end := min(i+16, len(b))
		fmt.Fprintf(&sb, "%08x  % x\n", i, b[i:end])
	}
	return sb.String()
}

func (c *cli) ssyncRoot(args []string, suite, key string, trashDays int, plain, exclude []string) error {
	if len(args) == 0 {
		return usagef("ssync root takes ls, add or rm")
	}
	switch args[0] {
	case "ls":
		roots, err := c.svc.SecureRoots()
		if err != nil {
			return err
		}
		for _, r := range roots {
			enc := "plain"
			if r.Method != "" {
				enc = r.Method + " key=" + r.KeyRef
			}
			fmt.Fprintf(c.io.Stdout, "%s\t%s\ts3://%s/%s\t%s\n", r.Name, r.Local, r.Bucket, r.Prefix, enc)
		}
		return nil
	case "add":
		if len(args) != 4 {
			return usagef("ssync root add takes NAME LOCAL s3://bucket/prefix/")
		}
		p, err := parseS3(args[3])
		if err != nil {
			return err
		}
		local, err := filepath.Abs(args[2])
		if err != nil {
			return err
		}
		if err := c.resolveAccount(); err != nil {
			return err
		}
		r, err := c.svc.SaveSecureRoot(app.SecureRoot{Name: args[1], AccountID: c.acct.ID, Bucket: p.Bucket, Prefix: p.Key,
			Local: local, Method: suite, KeyRef: key, PlainGlobs: plain, Excludes: exclude, TrashDays: trashDays})
		if err != nil {
			return err
		}
		c.infof("root %q added (%s)", r.Name, r.ID)
		return nil
	case "rm":
		if len(args) != 2 {
			return usagef("ssync root rm takes NAME")
		}
		return c.svc.DeleteSecureRoot(args[1])
	}
	return usagef("ssync root takes ls, add or rm")
}

func (c *cli) printSecureReport(rep app.SecureSyncReport) {
	for _, a := range rep.Actions {
		line := a.Op + "\t" + a.Path
		if a.Err != "" {
			line += "\tERROR: " + a.Err
		} else if a.Note != "" {
			line += "\t" + a.Note
		}
		fmt.Fprintln(c.io.Stdout, line)
	}
	for _, w := range rep.Warnings {
		c.infof("warning: %s", w)
	}
	c.printConflicts(rep.Conflicts)
}

func (c *cli) printConflicts(list []app.SecureConflict) {
	for _, x := range list {
		fmt.Fprintf(c.io.Stdout, "conflict\t%s\t%s", x.Path, x.Kind)
		if x.Local != nil {
			fmt.Fprintf(c.io.Stdout, "\tlocal %d bytes %s %s", x.Local.Size, x.Local.MTime.Format(time.RFC3339), x.Local.Hash)
		}
		if x.Remote != nil {
			fmt.Fprintf(c.io.Stdout, "\tremote %d bytes %s", x.Remote.Size, x.Remote.MTime.Format(time.RFC3339))
		}
		fmt.Fprintln(c.io.Stdout)
	}
}

func (c *cli) ssyncTrash(ctx context.Context, args []string, days int) error {
	if len(args) < 2 {
		return usagef("ssync trash takes NAME and ls, restore KEY or purge")
	}
	name := args[0]
	switch args[1] {
	case "ls":
		items, err := c.svc.SecureTrashList(ctx, name)
		if err != nil {
			return err
		}
		for _, it := range items {
			fmt.Fprintf(c.io.Stdout, "%s\t%s\t%d\t%s\n", it.Deleted.Format(time.RFC3339), it.Path, it.Size, it.Key)
		}
		return nil
	case "restore":
		if len(args) != 3 {
			return usagef("ssync trash NAME restore takes the trash KEY from ls")
		}
		if err := c.svc.SecureTrashRestore(ctx, name, args[2]); err != nil {
			return err
		}
		c.infof("restored; run pail ssync run %s to bring it down", name)
		return nil
	case "purge":
		n, err := c.svc.SecureTrashPurge(ctx, name, days)
		if err != nil {
			return err
		}
		c.infof("removed %d item(s) from the trash", n)
		return nil
	}
	return usagef("ssync trash takes ls, restore or purge")
}

// ssyncEdit opens the file in an editor and offers to save it back.
func (c *cli) ssyncEdit(ctx context.Context, name, rel, editor string) error {
	ed, err := c.svc.SecureEditOpen(ctx, name, rel)
	if err != nil {
		return err
	}
	defer c.svc.SecureEditClose(ed.ID)
	cmdline := editor
	if cmdline == "" {
		cmdline = os.Getenv("VISUAL")
	}
	if cmdline == "" {
		cmdline = os.Getenv("EDITOR")
	}
	if cmdline == "" {
		return usagef("no editor: set $VISUAL or $EDITOR, or pass --editor")
	}
	parts := strings.Fields(cmdline)
	cmd := exec.CommandContext(ctx, parts[0], append(parts[1:], ed.File)...)
	cmd.Stdin, cmd.Stdout, cmd.Stderr = os.Stdin, c.io.Stderr, c.io.Stderr
	if err := cmd.Run(); err != nil {
		return &exitErr{exitFailure, "the editor failed: " + err.Error()}
	}
	if ch, _ := c.svc.SecureEditChanged(ed.ID); !ch {
		c.infof("no changes")
		return nil
	}
	err = c.svc.SecureEditSave(ctx, ed.ID, app.SaveStrict)
	if err == nil {
		c.infof("saved %s", rel)
		return nil
	}
	if !app.IsKind(err, app.ErrConflict) {
		return err
	}
	// The remote changed meanwhile: keep the edit as a conflict copy, never lose it.
	c.infof("%v", err)
	if err := c.svc.SecureEditSave(ctx, ed.ID, app.SaveKeepBoth); err != nil {
		return err
	}
	c.infof("your edit was saved as a conflict copy; run pail ssync run %s", name)
	return nil
}
