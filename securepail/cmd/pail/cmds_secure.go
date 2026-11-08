package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"strings"

	"github.com/jstdlee/securePail/internal/app"
	"github.com/jstdlee/securePail/internal/seclayer"
)

// looksLikeRecovery reports whether b is a recovery key (64 hex digits).
func looksLikeRecovery(b []byte) bool {
	_, err := seclayer.ParseRecovery(string(b))
	return err == nil
}

func setupDoctor(c *cli, fs *flag.FlagSet) runner {
	require := fs.Bool("require-gpg", false, "treat gpg as required even if no upload rule uses a GPG layer yet")
	return func(ctx context.Context, pos []string) error {
		if len(pos) != 0 {
			return usagef("doctor takes no arguments")
		}
		rep := c.svc.ReadinessFor(ctx, *require)
		if c.g.json {
			for _, it := range rep.Items {
				c.emit(map[string]any{"type": "check", "id": it.ID, "name": it.Name, "required": it.Required,
					"status": it.Status, "path": it.Path, "version": it.Version, "detail": it.Detail, "hint": it.Hint})
			}
			c.emit(map[string]any{"type": "summary", "command": "doctor", "ok": rep.Ready})
		} else {
			fmt.Fprint(c.io.Stdout, rep.Render())
		}
		if !rep.Ready {
			return &exitErr{exitFailure, "not ready: a required component failed"}
		}
		return nil
	}
}

func setupSecure(c *cli, fs *flag.FlagSet) runner {
	format := fs.String("format", "keyfile", "export format: keyfile (portable JSON, no tools needed) or gpg")
	pwStdin := fs.Bool("password-stdin", false, "read the password from the first line of stdin")
	readPassword := func(prompt string) (string, error) {
		if *pwStdin {
			line, err := c.in.ReadString('\n')
			pw := strings.TrimRight(line, "\r\n")
			if pw == "" {
				if err != nil {
					return "", usagef("--password-stdin: no password on stdin (expected one line)")
				}
				return "", usagef("--password-stdin: the password line is empty")
			}
			return pw, nil
		}
		if c.io.ReadPassword == nil {
			return "", usagef("there is no terminal to ask for the password; pass --password-stdin")
		}
		return c.io.ReadPassword(prompt)
	}
	return func(ctx context.Context, pos []string) error {
		if len(pos) == 0 {
			return usagef("usage: pail secure keygen|passphrase|export|import ... (see pail help secure)")
		}
		sub, args := pos[0], pos[1:]
		done := func(msg string) error {
			if c.g.json {
				c.emit(map[string]any{"type": "summary", "command": "secure " + sub, "ok": true})
			} else {
				c.infof("%s", msg)
			}
			return nil
		}
		switch sub {
		case "suites":
			for _, st := range seclayer.Suites {
				if c.g.json {
					c.emit(map[string]any{"type": "suite", "id": st.ID, "name": st.Name, "needsGpg": st.NeedsGPG,
						"mobile": st.Mobile, "streaming": st.Streaming, "passphraseKeys": st.PassphraseKeys, "suffix": st.Suffix})
					continue
				}
				fmt.Fprintf(c.io.Stdout, "%-7s %s\n        %s\n", st.ID, st.Name, st.Summary)
			}
			return nil
		case "recovery":
			if len(args) != 1 {
				return usagef("secure recovery takes REF")
			}
			rec, err := c.svc.SecureRecoveryKey(ctx, args[0])
			if err != nil {
				return err
			}
			if c.g.json {
				c.emit(map[string]any{"type": "recovery", "ref": args[0], "recoveryKey": rec})
				return nil
			}
			fmt.Fprintln(c.io.Stdout, rec)
			return nil
		case "keygen":
			if len(args) != 1 {
				return usagef("secure keygen takes REF")
			}
			if err := c.svc.GenerateSecureKey(args[0]); err != nil {
				return err
			}
			return done(fmt.Sprintf("key %q created in the key store. Back it up now: pail secure export %s FILE", args[0], args[0]))
		case "passphrase":
			if len(args) != 1 {
				return usagef("secure passphrase takes REF")
			}
			pw, err := readPassword("Passphrase: ")
			if err != nil {
				return err
			}
			if !*pwStdin {
				again, err := readPassword("Repeat passphrase: ")
				if err != nil {
					return err
				}
				if again != pw {
					return usagef("the passphrases differ")
				}
			}
			if err := c.svc.SetSecurePassphrase(args[0], pw); err != nil {
				return err
			}
			return done(fmt.Sprintf("passphrase stored as %q", args[0]))
		case "export":
			if len(args) != 2 {
				return usagef("secure export takes REF and FILE")
			}
			if _, err := os.Stat(args[1]); err == nil {
				return usagef("%s exists; the key file is never overwritten", args[1])
			}
			pw, err := readPassword("Backup password: ")
			if err != nil {
				return err
			}
			b, err := c.svc.ExportSecureKey(ctx, args[0], pw, app.SecureKeyFormat(*format))
			if err != nil {
				return err
			}
			if err := os.WriteFile(args[1], b, 0o600); err != nil {
				return err
			}
			if *format == "gpg" {
				return done(fmt.Sprintf("wrote %s; open it with: gpg -d %s", args[1], args[1]))
			}
			return done(fmt.Sprintf("wrote %s (portable key file, opens in securePail on any platform)", args[1]))
		case "import":
			if len(args) != 2 {
				return usagef("secure import takes REF and FILE")
			}
			b, err := os.ReadFile(args[1])
			if err != nil {
				b = []byte(args[1]) // not a file: maybe a recovery key
			}
			pw := ""
			if seclayer.IsKeyFile(b) || !looksLikeRecovery(b) {
				if pw, err = readPassword("Backup password: "); err != nil {
					return err
				}
			}
			if err := c.svc.ImportSecureKey(ctx, args[0], b, pw); err != nil {
				return err
			}
			return done(fmt.Sprintf("key restored as %q", args[0]))
		}
		return usagef("unknown secure subcommand %q", sub)
	}
}
