package main

import (
	"fmt"
	"os"
	"path/filepath"
	"syscall"
)

const realBwrap = "/run/ush/bwrap"

func isBwrapShim() bool {
	return filepath.Base(os.Args[0]) == "bwrap"
}

func runBwrapShim() int {
	if _, err := os.Stat(realBwrap); err != nil {
		fmt.Fprintf(os.Stderr, "bwrap: %v\n", err)
		return 127
	}
	if err := dropAmbientCaps(); err != nil {
		fmt.Fprintf(os.Stderr, "bwrap: %v\n", err)
		return 1
	}
	err := syscall.Exec(realBwrap, append([]string{"bwrap"}, os.Args[1:]...), os.Environ())
	fmt.Fprintf(os.Stderr, "bwrap: %v\n", err)
	return 1
}
