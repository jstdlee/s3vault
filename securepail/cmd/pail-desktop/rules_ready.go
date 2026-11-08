package main

import (
	"fmt"
	"time"

	"github.com/egoist/mygo/ui"

	"github.com/jstdlee/securePail/cmd/pail-desktop/locales"
	"github.com/jstdlee/securePail/internal/readiness"
)

// readyState is the result of the secure layer's component check, shown under
// the GPG layer settings in the upload rules.
type readyState struct {
	running bool
	done    bool
	lines   []string // one per problem; empty with done = everything works
}

// readinessRow renders the "Check components" button and its result.
func (a *app) readinessRow(c *ui.Context, requireGPG bool) {
	rs := &a.tl.rules.ready
	ui.Row(c).Gap(12).Children(func() {
		if secondaryButton(c, locales.RulesReadyCheck(), rs.running).Clicked() {
			a.runReadiness(requireGPG)
		}
		switch {
		case rs.running:
			ui.Text(c, locales.RulesReadyRunning())
		case rs.done && len(rs.lines) == 0:
			ui.Text(c, locales.RulesReadyAll())
		}
	})
	for _, l := range rs.lines {
		ui.Text(c, l)
	}
}

// runReadiness checks the components off the UI thread. gpg counts as
// required only when the GPG suite is chosen.
func (a *app) runReadiness(requireGPG bool) {
	rs := &a.tl.rules.ready
	if rs.running {
		return
	}
	rs.running, rs.done, rs.lines = true, false, nil
	ctx, cancel := a.timeout(45 * time.Second)
	go func() {
		defer cancel()
		rep := a.svc.ReadinessFor(ctx, requireGPG)
		a.post(func() {
			st := &a.tl.rules.ready
			st.running, st.done = false, true
			st.lines = readyLines(rep)
		})
	}()
}

// readyLines words every item that is not OK; the zero-length result means ready.
func readyLines(rep readiness.Report) []string {
	var out []string
	for _, it := range rep.Items {
		if it.Status == readiness.OK {
			continue
		}
		line := locales.RulesReadyItem(it.Name, it.Detail)
		if it.Hint != "" {
			line += " " + it.Hint
		}
		out = append(out, line)
	}
	return out
}

// newSecureKey creates a generated key under the next free name and selects it.
func (a *app) newSecureKey(target *string) {
	taken := map[string]bool{}
	for _, r := range a.svc.SecretRefs() {
		taken[r] = true
	}
	name := "secure-key"
	for i := 2; taken[name]; i++ {
		name = fmt.Sprintf("secure-key-%d", i)
	}
	if err := a.svc.GenerateSecureKey(name); err != nil {
		a.tl.rules.err = err.Error()
		return
	}
	*target = name
}
