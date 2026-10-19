package main

import (
	"syscall"

	"golang.org/x/sys/unix"
)

func dropAmbientCaps() error {
	if _, _, errno := syscall.AllThreadsSyscall(syscall.SYS_PRCTL, unix.PR_CAP_AMBIENT, unix.PR_CAP_AMBIENT_CLEAR_ALL, 0); errno != 0 {
		return errno
	}
	return nil
}
