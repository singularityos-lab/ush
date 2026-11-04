package main

import (
	"context"
	"errors"
	"fmt"
	"os"
	"strings"
	"syscall"

	"mvdan.cc/sh/v3/interp"

	"github.com/singularityos-lab/ush/internal/shell"
)

// onSIXKernel reports whether ush runs on the SIX kernel through its Linux
// compatibility layer. SIX identifies itself in the uname version field.
func onSIXKernel() bool {
	var u syscall.Utsname
	if syscall.Uname(&u) != nil {
		return false
	}
	var b strings.Builder
	for _, c := range u.Version {
		if c == 0 {
			break
		}
		b.WriteByte(byte(c))
	}
	return strings.HasPrefix(b.String(), "SIX ")
}

// sixConfined reports whether a namespace setup failure means the process is
// a confined task on SIX. SIX refuses namespace creation to confined Linux
// tasks and enforces their containment with its own MAC policy, so the ush
// sandbox is neither available nor needed there.
func sixConfined(err error) bool {
	return errors.Is(err, syscall.EPERM) && onSIXKernel()
}

// runSIXConfined runs the ush interpreter in the current process, under the
// containment SIX already applies to it.
func runSIXConfined(sessionID, storageDir string) error {
	sh, err := shell.New(&shell.Config{SessionID: sessionID, StorageDir: storageDir})
	if err != nil {
		return err
	}
	ctx := context.Background()
	switch {
	case os.Getenv("USH_CMD") != "":
		err = sh.RunScript(ctx, strings.NewReader(os.Getenv("USH_CMD")), "ush")
	case !stdinIsTTY():
		err = sh.RunScript(ctx, os.Stdin, "stdin")
	default:
		fmt.Fprintln(os.Stderr, "ush: running under SIX confinement, without the ush sandbox")
		err = sh.RunInteractive(ctx)
	}
	var status interp.ExitStatus
	if errors.As(err, &status) {
		return guestExit(int(status))
	}
	return err
}
