package main

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"mvdan.cc/sh/v3/interp"

	"github.com/singularityos-lab/ush/internal/shell"
)

func isGosh() bool {
	return filepath.Base(os.Args[0]) == "gosh"
}

func runGosh() int {
	sh, err := shell.New(&shell.Config{
		SessionID:  os.Getenv("USH_SESSION_ID"),
		StorageDir: os.Getenv("USH_STORAGE_DIR"),
	})
	if err != nil {
		fmt.Fprintf(os.Stderr, "gosh: %v\n", err)
		return 1
	}
	ctx := context.Background()
	args := os.Args[1:]
	switch {
	case len(args) >= 2 && args[0] == "-c":
		err = sh.RunLine(ctx, args[1])
	case len(args) >= 1 && args[0] != "-":
		f, oerr := os.Open(args[0])
		if oerr != nil {
			fmt.Fprintf(os.Stderr, "gosh: %v\n", oerr)
			return 127
		}
		defer f.Close()
		err = sh.RunScript(ctx, f, args[0])
	case !stdinIsTTY():
		err = sh.RunScript(ctx, os.Stdin, "stdin")
	default:
		err = sh.RunInteractive(ctx)
	}
	var status interp.ExitStatus
	if errors.As(err, &status) {
		return int(status)
	}
	if err != nil {
		fmt.Fprintf(os.Stderr, "gosh: %v\n", err)
		return 1
	}
	return 0
}
